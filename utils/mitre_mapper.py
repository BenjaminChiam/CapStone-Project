"""
MITRE ATT&CK Mapper Module
Uses OpenAI GPT-4o to map IOCs to MITRE ATT&CK Techniques with reasoning.
Includes local validation to prevent LLM hallucinations of non-existent Technique IDs.
"""

import json
from openai import OpenAI
from typing import Optional
from utils.mitre_data import VALID_MITRE_TECHNIQUES


class MITREMapper:
    """
    Maps enriched IOC data to MITRE ATT&CK TTPs using GPT-4o.
    Validates all returned Technique IDs against a local dictionary
    to prevent hallucinated IDs from reaching the dashboard.
    """

    SYSTEM_PROMPT = """You are an expert Cyber Threat Intelligence (CTI) Analyst specializing in the MITRE ATT&CK Enterprise Matrix.

Your task: Given an enriched IOC payload, map the indicator to the most relevant MITRE ATT&CK Technique(s).

STRICT RULES:
1. ONLY use valid MITRE ATT&CK Enterprise Matrix Technique IDs (e.g., T1071, T1059.001).
2. DO NOT invent or fabricate Technique IDs.
3. Provide a confidence level: HIGH, MEDIUM, or LOW.
4. ALWAYS include a one-sentence "reasoning" explaining WHY you chose this mapping.
5. If you cannot determine a mapping, return technique_id as "UNKNOWN".

Respond ONLY with valid JSON in this exact schema:
{
    "mappings": [
        {
            "technique_id": "T1071.001",
            "technique_name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "confidence": "HIGH",
            "reasoning": "The presence of Cobalt Strike beacon on port 443 indicates C2 over HTTPS."
        }
    ],
    "overall_assessment": "Brief one-line threat summary",
    "recommended_actions": ["action1", "action2"]
}"""

    def __init__(self, openai_api_key: str = ""):
        self.api_key = openai_api_key
        self.client = OpenAI(api_key=openai_api_key) if openai_api_key else None

    def _validate_technique_id(self, technique_id: str) -> bool:
        """Validate a MITRE Technique ID against the local dictionary."""
        if technique_id == "UNKNOWN":
            return True
        return technique_id in VALID_MITRE_TECHNIQUES

    def _build_user_prompt(self, ioc: str, enrichment_data: Optional[dict] = None) -> str:
        """Build the user prompt with IOC and enrichment context."""
        prompt = f"Analyze this IOC and map it to MITRE ATT&CK:\n\nIOC: {ioc}\n"

        if enrichment_data:
            prompt += f"\nEnrichment Data:\n```json\n{json.dumps(enrichment_data, indent=2)}\n```"
        else:
            prompt += "\nNo enrichment data available. Map based on the IOC type and any observable characteristics."

        return prompt

    def map_ioc(self, ioc: str, enrichment_data: Optional[dict] = None) -> dict:
        """
        Map an IOC to MITRE ATT&CK using GPT-4o.
        Returns validated mapping with reasoning.
        """
        if not self.client:
            return self._fallback_response(ioc, "OpenAI API key not configured")

        user_prompt = self._build_user_prompt(ioc, enrichment_data)

        try:
            response = self.client.chat.completions.create(
                model="gpt-4o",
                messages=[
                    {"role": "system", "content": self.SYSTEM_PROMPT},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_object"},
                temperature=0.1,
                max_tokens=1500,
                timeout=30,
            )

            raw = response.choices[0].message.content
            result = json.loads(raw)

            # Validate all technique IDs
            validated_mappings = []
            for mapping in result.get("mappings", []):
                tid = mapping.get("technique_id", "UNKNOWN")
                if self._validate_technique_id(tid):
                    validated_mappings.append(mapping)
                else:
                    # Replace hallucinated ID with UNKNOWN
                    mapping["technique_id"] = "UNKNOWN"
                    mapping["reasoning"] = (
                        f"[VALIDATION FAILED] Original ID '{tid}' is not a valid MITRE Technique. "
                        + mapping.get("reasoning", "")
                    )
                    validated_mappings.append(mapping)

            result["mappings"] = validated_mappings
            result["ioc"] = ioc
            result["validation"] = "All technique IDs validated against local MITRE dictionary"
            return result

        except json.JSONDecodeError:
            return self._fallback_response(ioc, "Failed to parse LLM JSON response")
        except Exception as e:
            return self._fallback_response(ioc, str(e))

    @staticmethod
    def _fallback_response(ioc: str, error: str) -> dict:
        """Return a safe fallback when the LLM call fails."""
        return {
            "ioc": ioc,
            "mappings": [
                {
                    "technique_id": "UNKNOWN",
                    "technique_name": "Unable to determine",
                    "tactic": "Unknown",
                    "confidence": "LOW",
                    "reasoning": f"Automated mapping failed: {error}",
                }
            ],
            "overall_assessment": "Manual analyst review required.",
            "recommended_actions": ["Manually investigate this IOC", "Check against internal threat intel"],
            "error": error,
        }
