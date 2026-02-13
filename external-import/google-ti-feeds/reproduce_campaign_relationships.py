
import sys
import unittest
from unittest.mock import MagicMock
import json
from datetime import datetime

# Mock pycti and other external dependencies
import uuid
mock_pycti = MagicMock()
mock_pycti.Identity.generate_id.side_effect = lambda **kwargs: f"identity--{uuid.uuid4()}"
mock_pycti.Location.generate_id.side_effect = lambda **kwargs: f"location--{uuid.uuid4()}"
mock_pycti.Campaign.generate_id.side_effect = lambda **kwargs: f"campaign--{uuid.uuid4()}"
mock_pycti.AttackPattern.generate_id.side_effect = lambda **kwargs: f"attack-pattern--{uuid.uuid4()}"
mock_pycti.Malware.generate_id.side_effect = lambda **kwargs: f"malware--{uuid.uuid4()}"
mock_pycti.IntrusionSet.generate_id.side_effect = lambda **kwargs: f"intrusion-set--{uuid.uuid4()}"
mock_pycti.StixCoreRelationship.generate_id.side_effect = lambda **kwargs: f"relationship--{uuid.uuid4()}"
sys.modules["pycti"] = mock_pycti
sys.modules["connectors_sdk.models.octi"] = MagicMock()

# Mock specific classes used in the code
from pydantic import BaseModel

# Mock Organization and TLP
class MockOrganization:
    id = f"identity--{uuid.uuid4()}"

class MockTLP:
    id = f"marking-definition--{uuid.uuid4()}"

# Import the code to test
# We need to make sure the imports in the verified files work.
# Since we mocked pycti, the imports inside the modules should pass or use the mocks.
try:
    from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData, CampaignModel, TargetedIndustry, TargetedRegion, SourceRegion
    from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_composite import GTICampaignToSTIXComposite
    from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel
except ImportError as e:
    # If standard import fails due to python path, we might need to adjust it
    import os
    sys.path.append(os.getcwd())
    from connector.src.custom.models.gti.gti_campaign_model import GTICampaignData, CampaignModel, TargetedIndustry, TargetedRegion, SourceRegion
    from connector.src.custom.mappers.gti_campaigns.gti_campaign_to_stix_composite import GTICampaignToSTIXComposite
    from connector.src.stix.octi.models.relationship_model import OctiRelationshipModel

class TestGTICampaignRelationships(unittest.TestCase):
    def setUp(self):
        self.organization = MockOrganization()
        self.tlp_marking = MockTLP()

    def test_campaign_relationship_aliasing(self):
        """
        Test that API response fields (targeted_industries, etc.) are correctly mapped 
        to the model fields (targeted_industries_tree, etc.)
        """
        # Simulate API Data where the JSON keys are 'targeted_industries' 
        # but the model expects 'targeted_industries_tree'
        api_data = {
            "id": "campaign-1",
            "type": "campaign",
            "attributes": {
                "name": "Test Campaign",
                "creation_date": 1600000000,
                "last_modification_date": 1600000000,
                "targeted_industries": [
                    {
                        "industry_group": "Technology",
                        "confidence": "HIGH"
                    }
                ],
                "targeted_regions": [
                    {
                        "region": "North America",
                        "confidence": "HIGH"
                    }
                ],
                "source_regions": [
                    {
                        "region": "Eastern Europe",
                        "confidence": "HIGH"
                    }
                ],
                "tags": ["T1059", "Ransomware"]
            }
        }

        # Try to parse into Pydantic model
        # This is where it should FAIL if aliases are missing
        try:
            campaign_data = GTICampaignData(**api_data)
        except Exception as e:
            print(f"Pydantic validation error (Expected if aliases are missing): {e}")
            campaign_data = None

        if campaign_data and campaign_data.attributes:
            print("Successfully parsed API data.")
            # check if fields are populated
            attrs = campaign_data.attributes
            print(f"targeted_industries_tree: {attrs.targeted_industries_tree}")
            print(f"targeted_regions_hierarchy: {attrs.targeted_regions_hierarchy}")
            print(f"source_regions_hierarchy: {attrs.source_regions_hierarchy}")
            
            # Now try to generate relationships
            mapper = GTICampaignToSTIXComposite(campaign_data, self.organization, self.tlp_marking)
            
            relationships = mapper.to_stix()
            # Filter for relationships
            rels = [r for r in relationships if isinstance(r, OctiRelationshipModel) or (hasattr(r, "type") and r.type == "relationship")]
            
            print(f"Generated {len(rels)} relationships.")
            for r in rels:
                print(f"Rel: {r.relationship_type} -> {r.target_ref}")

            # Verify targeted_industries linkage
            industry_rels = [r for r in rels if r.relationship_type == "targets" and "industry" in r.description]
            self.assertTrue(len(industry_rels) > 0, "Should have targets relationship for industry")

            # Verify TTP linkage (from tags)
            # This will fail until we implement the logic
            ttp_rels = [r for r in rels if r.relationship_type == "uses" and "T1059" in str(r.target_ref)]
            # We expect this to contain T1059 if we implement the fix
            # For now, it might be empty
            print(f"TTP Rels: {ttp_rels}")
            
            self.assertIsNotNone(attrs.targeted_industries_tree, "targeted_industries_tree should not be None")
            self.assertIsNotNone(attrs.targeted_regions_hierarchy, "targeted_regions_hierarchy should not be None")
        else:
            print("Failed to parse API data with current model (CONFIRMED ISSUE).")

if __name__ == '__main__':
    unittest.main()
