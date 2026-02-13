
import sys
import os
import logging
from datetime import datetime, timezone

# Add the current directory to sys.path so we can import connector modules
sys.path.append(os.getcwd())

from connector.src.custom.mappers.gti_threat_actors.gti_threat_actor_to_stix_composite import GTIThreatActorToSTIXComposite
from connector.src.custom.models.gti.gti_threat_actor_model import GTIThreatActorData, ThreatActorModel, TargetedIndustry
from connectors_sdk.models.octi import OrganizationAuthor, TLPMarking
from stix2 import Relationship

# Mock Logger
logger = logging.getLogger("test")
logging.basicConfig(level=logging.INFO)

def test_relationship_creation():
    # 1. Create Mock Data
    targeted_industry = TargetedIndustry(
        confidence="High",
        industry_group="Financial Services",
        description="Targeting banks",
        first_seen=int(datetime(2023, 1, 1).timestamp()),
        last_seen=int(datetime(2023, 12, 31).timestamp())
    )

    attributes = ThreatActorModel(
        name="Test Actor",
        creation_date=int(datetime(2023, 1, 1).timestamp()),
        last_modification_date=int(datetime(2023, 12, 31).timestamp()),
        private=False,
        targeted_industries_tree=[targeted_industry]
    )

    threat_actor_data = GTIThreatActorData(
        id="test-actor-id",
        attributes=attributes,
        links={"self": "http://test"}
    )

    organization = OrganizationAuthor(
        name="Test Org",
        description="Test Description",
        contact_information="http://test.com"
    )

    tlp_marking = TLPMarking(level="white")

    # 2. Run Composite Mapper
    mapper = GTIThreatActorToSTIXComposite(
        threat_actor=threat_actor_data,
        organization=organization,
        tlp_marking=tlp_marking
    )

    stix_objects = mapper.to_stix()

    # 3. specific check for relationships
    relationships = [obj for obj in stix_objects if obj["type"] == "relationship"]
    
    print(f"Total STIX Objects: {len(stix_objects)}")
    print(f"Relationships found: {len(relationships)}")
    
    found_target_sector = False
    for rel in relationships:
        print(f"Relationship: {rel['source_ref']} -> {rel['relationship_type']} -> {rel['target_ref']}")
        if rel["relationship_type"] == "targets" and "identity--" in rel["target_ref"]:
            found_target_sector = True
            print("FOUND: targets relationship to identity (sector)")

    if found_target_sector:
        print("SUCCESS: Sector targeting relationship created.")
    else:
        print("FAILURE: Sector targeting relationship NOT found.")

if __name__ == "__main__":
    test_relationship_creation()
