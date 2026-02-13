import re
from datetime import datetime, timezone
from typing import Any

from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_identity import (
    GTIThreatActorToSTIXIdentity,
    IdentityWithTiming,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_intrusion_set import (
    GTIThreatActorToSTIXIntrusionSet,
)
from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_location import (
    GTIThreatActorToSTIXLocation,
    LocationWithTiming,
)
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData
from connector.src.stix.octi.models.attack_pattern_model import OctiAttackPatternModel
from connector.src.stix.octi.models.malware_model import OctiMalwareModel
from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
from connector.src.stix.v21.models.ovs.malware_type_ov_enums import MalwareTypeOV
from connector.src.utils.converters.generic_converter_config import BaseMapper
from connectors_sdk.models.octi import (  # type: ignore[import-untyped]
    OrganizationAuthor,
    TLPMarking,
)


class GTIThreatActorToSTIXComposite(BaseMapper):
    """Composite mapper that converts a GTI threat actor to country locations, identity, intrusion set, and relationships."""

    def __init__(
        self,
        threat_actor: GTIThreatActorData,
        organization: OrganizationAuthor,
        tlp_marking: TLPMarking,
        enable_threat_actor_aliases: bool = False,
    ) -> None:
        """Initialize the composite mapper.

        Args:
            threat_actor: The GTI threat actor data to convert
            organization: The organization identity object
            tlp_marking: The TLP marking definition
            enable_threat_actor_aliases: Whether to enable importing threat actor aliases

        """
        self.threat_actor = threat_actor
        self.organization = organization
        self.tlp_marking = tlp_marking
        self.enable_threat_actor_aliases = enable_threat_actor_aliases

    def to_stix(self) -> list[Any]:
        """Convert the GTI threat actor to a list of STIX objects (country locations, sectors, intrusion_set, relationships).

        Returns:
            list of STIX objects in order: [country_locations..., sectors..., intrusion_set, relationships...]

        """
        all_entities = []

        location_mapper = GTIThreatActorToSTIXLocation(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        locations_with_timing = location_mapper.to_stix_with_timing()
        country_locations = [item.location for item in locations_with_timing]
        all_entities.extend(country_locations)

        identity_mapper = GTIThreatActorToSTIXIdentity(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
        )
        sectors_with_timing = identity_mapper.to_stix_with_timing()
        sectors = [item.identity for item in sectors_with_timing]
        all_entities.extend(sectors)

        intrusion_set_mapper = GTIThreatActorToSTIXIntrusionSet(
            threat_actor=self.threat_actor,
            organization=self.organization,
            tlp_marking=self.tlp_marking,
            enable_threat_actor_aliases=self.enable_threat_actor_aliases,
        )
        intrusion_set = intrusion_set_mapper.to_stix()
        all_entities.append(intrusion_set)

        relationships = self._create_relationships(
            intrusion_set, locations_with_timing, sectors_with_timing
        )
        all_entities.extend(relationships)

        return all_entities

    def _create_relationships(
        self,
        intrusion_set: Any,
        locations_with_timing: list[LocationWithTiming],
        sectors_with_timing: list[IdentityWithTiming],
    ) -> list[Any]:
        """Create relationships between the intrusion set and other entities.

        Args:
            intrusion_set: The intrusion set object
            locations_with_timing: list of LocationWithTiming objects containing location and timing data
            sectors_with_timing: list of IdentityWithTiming objects containing sector identity and timing data

        Returns:
            list of relationship objects

        """
        relationships: list[Any] = []

        if (
            not hasattr(self.threat_actor, "attributes")
            or not self.threat_actor.attributes
        ):
            return relationships

        attributes = self.threat_actor.attributes
        created = datetime.fromtimestamp(attributes.creation_date, tz=timezone.utc)
        modified = datetime.fromtimestamp(
            attributes.last_modification_date, tz=timezone.utc
        )

        targeted_locations_with_timing = self._get_targeted_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in targeted_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' targets location '{location.name}'",
            )
            relationships.append(relationship)

        source_locations_with_timing = self._get_source_locations_with_timing(
            locations_with_timing
        )
        for location_with_timing in source_locations_with_timing:
            location = location_with_timing.location
            relationship = OctiRelationshipModel.create(
                relationship_type="originates-from",
                source_ref=intrusion_set.id,
                target_ref=location.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=location_with_timing.first_seen,
                stop_time=location_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' originates from location '{location.name}'",
            )
            relationships.append(relationship)

        for sector_with_timing in sectors_with_timing:
            sector = sector_with_timing.identity
            relationship = OctiRelationshipModel.create(
                relationship_type="targets",
                source_ref=intrusion_set.id,
                target_ref=sector.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                start_time=sector_with_timing.first_seen,
                stop_time=sector_with_timing.last_seen,
                description=f"Threat actor '{attributes.name}' targets sector '{sector.name}'",
            )
            relationships.append(relationship)
        
        # Create relationships between threat actor and Attack Patterns (TTPs)
        # Threat Actor might use tags too?
        # Checking gti_threat_actor_model.py... it has 'tags'.
        if attributes.tags:
            ttp_objects = self._create_uses_attack_pattern_relationships(
                intrusion_set, attributes.tags, created, modified
            )
            relationships.extend(ttp_objects)
            
        # Malware check
        if (
            attributes.aggregations
            and attributes.aggregations.files
            and attributes.aggregations.files.suggested_threat_label
        ):
            malware_labels = attributes.aggregations.files.suggested_threat_label
            if isinstance(malware_labels, str):
                malware_labels = [malware_labels]
                
            malware_objects = self._create_uses_malware_relationships(
                intrusion_set, malware_labels, created, modified
            )
            relationships.extend(malware_objects)

        return relationships

    def _create_uses_attack_pattern_relationships(
        self,
        source_entity: Any,
        tags: list[str],
        created: datetime,
        modified: datetime,
    ) -> list[Any]:
        """Create Attack Patterns from tags and link them to the entity."""
        entities: list[Any] = []
        mitre_pattern = re.compile(r"T\d{4}(?:\.\d{3})?")

        for tag in tags:
            match = mitre_pattern.fullmatch(tag)
            if match:
                mitre_id = match.group(0)
                attack_pattern = OctiAttackPatternModel.create(
                    name=mitre_id,
                    mitre_id=mitre_id,
                    organization_id=self.organization.id,
                    marking_ids=[self.tlp_marking.id],
                    description=f"Technique {mitre_id} extracted from tags",
                    created=created,
                    modified=modified,
                )
                entities.append(attack_pattern)

                relationship = OctiRelationshipModel.create(
                    relationship_type="uses",
                    source_ref=source_entity.id,
                    target_ref=attack_pattern.id,
                    organization_id=self.organization.id,
                    marking_ids=[self.tlp_marking.id],
                    created=created,
                    modified=modified,
                    description=f"Threat actor uses technique {mitre_id}",
                )
                entities.append(relationship)
        
        return entities

    def _create_uses_malware_relationships(
        self,
        source_entity: Any,
        malware_names: list[str],
        created: datetime,
        modified: datetime,
    ) -> list[Any]:
        """Create Malware objects from names and link them to the entity."""
        entities: list[Any] = []
        
        for name in malware_names:
            msg = f"Malware family {name} extracted from suggested threat label"
            
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

            relationship = OctiRelationshipModel.create(
                relationship_type="uses",
                source_ref=source_entity.id,
                target_ref=malware.id,
                organization_id=self.organization.id,
                marking_ids=[self.tlp_marking.id],
                created=created,
                modified=modified,
                description=f"Threat actor uses malware {name}",
            )
            entities.append(relationship)
            
        return entities

    def _get_targeted_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to targeted countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to targeted countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_targeted
        ]

    def _get_source_locations_with_timing(
        self, locations_with_timing: list[LocationWithTiming]
    ) -> list[LocationWithTiming]:
        """Get LocationWithTiming objects that correspond to source countries.

        Args:
            locations_with_timing: list of all LocationWithTiming objects

        Returns:
            list of LocationWithTiming objects that correspond to source countries

        """
        return [
            location_with_timing
            for location_with_timing in locations_with_timing
            if location_with_timing.is_source
        ]
