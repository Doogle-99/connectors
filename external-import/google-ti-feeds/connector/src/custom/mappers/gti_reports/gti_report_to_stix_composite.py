import re
from datetime import datetime
from typing import Any

from connector.src.custom.mappers.gti_reports.gti_report_to_stix_identity import (
    GTIReportToSTIXIdentity,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_location import (
    GTIReportToSTIXLocation,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_report import (
    GTIReportToSTIXReport,
)
from connector.src.custom.mappers.gti_reports.gti_report_to_stix_sector import (
    GTIReportToSTIXSector,
)
from connector.src.custom.models.gti.gti_report_model import GTIReportData
from connector.src.stix.octi.models.attack_pattern_model import OctiAttackPatternModel
from connector.src.stix.octi.models.malware_model import OctiMalwareModel
from connector.src.stix.v21.models.ovs.malware_type_ov_enums import MalwareTypeOV
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIReportToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI report to locations, identity, and report STIX objects."""

    def __init__(
        self,
        report: GTIReportData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            report: The GTI report data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition

        """
        self.report = report
        self.organization = organization
        self.tlp_marking = tlp_marking

    def to_stix(self) -> list[Any]:
        """Convert the GTI report to a list of STIX objects (locations, sectors, identity, report).

        Returns:
            list of STIX objects in order: [locations..., sectors..., identity, report, referenced_objects...]

        """
        all_entities = []

        location_mapper = GTIReportToSTIXLocation(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations = location_mapper.to_stix()
        all_entities.extend(locations)

        sector_mapper = GTIReportToSTIXSector(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors = sector_mapper.to_stix()
        all_entities.extend(sectors)

        identity_mapper = GTIReportToSTIXIdentity(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        author_identity = identity_mapper.to_stix()
        all_entities.append(author_identity)

        report_mapper = GTIReportToSTIXReport(
            report=self.report,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )

        report_mapper.add_author_identity(author_identity)

        report_stix = report_mapper.to_stix()

        location_ids = [loc.id for loc in locations]
        sector_ids = [sector.id for sector in sectors]
        
        # Create and link Attack Patterns (TTPs)
        attack_patterns = []
        if self.report.attributes and self.report.attributes.tags_details:
            tags = [t.value for t in self.report.attributes.tags_details]
            attack_patterns = self._create_attack_patterns(tags)
            all_entities.extend(attack_patterns)
            
        ttp_ids = [ap.id for ap in attack_patterns]
        
        # Create and link Malware
        malwares = []
        if (
            self.report.attributes
            and self.report.attributes.aggregations
            and self.report.attributes.aggregations.files
            and self.report.attributes.aggregations.files.suggested_threat_label
        ):
            malware_labels = self.report.attributes.aggregations.files.suggested_threat_label
            if isinstance(malware_labels, str):
                malware_labels = [malware_labels]
            malwares = self._create_malwares(malware_labels)
            all_entities.extend(malwares)
            
        malware_ids = [m.id for m in malwares]

        report_stix = GTIReportToSTIXReport.add_object_refs(location_ids, report_stix)
        report_stix = GTIReportToSTIXReport.add_object_refs(sector_ids, report_stix)
        report_stix = GTIReportToSTIXReport.add_object_refs(ttp_ids, report_stix)
        report_stix = GTIReportToSTIXReport.add_object_refs(malware_ids, report_stix)

        all_entities.append(report_stix)

        return all_entities

    def _create_attack_patterns(self, tags: list[str]) -> list[Any]:
        """Create Attack Patterns from tags."""
        entities: list[Any] = []
        mitre_pattern = re.compile(r"T\d{4}(?:\.\d{3})?")
        
        # Default dates if not available (ideally should come from report)
        created = datetime.now()
        modified = datetime.now()
        if self.report.attributes:
             # creating datetime object from timestamp
             # assuming timestamps are in seconds
             # check model: creation_date: int
             pass

        for tag in tags:
            match = mitre_pattern.fullmatch(tag)
            if match:
                mitre_id = match.group(0)
                attack_pattern = OctiAttackPatternModel.create(
                    name=mitre_id,
                    mitre_id=mitre_id,
                    organization_id=self.organization.id,
                    marking_ids=[self.tlp_marking.id],
                    description=f"Technique {mitre_id} extracted from report tags",
                    created=created,
                    modified=modified,
                )
                entities.append(attack_pattern)
        return entities

    def _create_malwares(self, malware_names: list[str]) -> list[Any]:
        """Create Malware objects from names."""
        entities: list[Any] = []
        created = datetime.now()
        modified = datetime.now()

        for name in malware_names:
            msg = f"Malware family {name} extracted from report aggregations"
            malware = OctiMalwareModel.create(
                name=name,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                malware_types=[MalwareTypeOV.RANSOMWARE if "ransom" in name.lower() else MalwareTypeOV.UNKNOWN],
                is_family=True,
                description=msg,
                created=created,
                modified=modified,
            )
            entities.append(malware)
        return entities
