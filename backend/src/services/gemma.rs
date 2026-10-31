use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::env;

const API_BASE: &str = "https://generativelanguage.googleapis.com/v1beta/models";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GemmaAssessment {
    pub classification: String,
    pub risk_level: String,
    pub confidence: u8,
    pub summary: String,
    pub evidence: Vec<String>,
    pub recommendations: Vec<String>,
    pub limitations: Vec<String>,
}

pub struct GemmaClient {
    client: Client,
    api_key: String,
    model: String,
}

#[derive(Debug, Deserialize)]
struct GemmaApiResponse {
    candidates: Vec<Candidate>,
}

#[derive(Debug, Deserialize)]
struct Candidate {
    content: CandidateContent,

    #[serde(rename = "finishReason")]
    finish_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CandidateContent {
    parts: Vec<CandidatePart>,
}

#[derive(Debug, Deserialize)]
struct CandidatePart {
    text: Option<String>,
    thought: Option<bool>,
}

impl GemmaClient {
    pub fn from_env() -> Result<Self, String> {
        dotenvy::dotenv().ok();

        let api_key = env::var("GEMINI_API_KEY")
            .map_err(|_| "GEMINI_API_KEY is missing from the environment".to_string())?;

        let model = env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemma-4-26b-a4b-it".to_string());

        Ok(Self {
            client: Client::new(),
            api_key,
            model,
        })
    }

    pub async fn analyze_alert(&self, alert: &Value) -> Result<GemmaAssessment, String> {
        let prompt = format!(
            r#"
You are SentinelAI, a cybersecurity SOC analyst.

Analyse the following network security alert.

ALERT:
{}

Rules:
- Treat the alert as evidence, not proof of an attack.
- Do not invent IP reputation, geolocation, packet details, or events.
- Distinguish observed facts from your interpretation.
- Explain uncertainty and missing evidence.
- Recommend defensive investigation steps.
- Do not recommend automatically blocking any host.
- Return only valid JSON. Do not include Markdown or explanations outside JSON.
- Do not include private reasoning or internal thought processes.

Use exactly this JSON structure:
{{
  "classification": "short threat classification",
  "risk_level": "Low, Medium, High, or Critical",
  "confidence": 50,
  "summary": "Brief assessment",
  "evidence": ["observed fact supporting the assessment"],
  "recommendations": ["defensive investigation step"],
  "limitations": ["what cannot be concluded from the supplied evidence"]
}}

Confidence must be an integer from 0 to 100.
"#,
            alert
        );

        let url = format!("{}/{}/:generateContent", API_BASE, self.model);

        let request_body = json!({
            "contents": [{
                "parts": [{
                    "text": prompt
                }]
            }],
            "generationConfig": {
                "temperature": 0.2,
                "maxOutputTokens": 2048,
                "thinkingConfig": {
                    "thinkingLevel": "minimal"
                }
            }
        });

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("x-goog-api-key", &self.api_key)
            .json(&request_body)
            .send()
            .await
            .map_err(|error| format!("Gemma request failed: {}", error))?;

        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| format!("Could not read Gemma response: {}", error))?;

        if !status.is_success() {
            return Err(format!("Gemma API returned HTTP {}: {}", status, body));
        }

        let api_response: GemmaApiResponse = serde_json::from_str(&body)
            .map_err(|error| format!("Invalid Gemma API response: {}", error))?;

        let candidate = api_response
            .candidates
            .first()
            .ok_or("Gemma returned no candidates")?;

        // Use final response text only. Exclude parts marked as internal thoughts.
        let final_text = candidate
            .content
            .parts
            .iter()
            .filter(|part| part.thought != Some(true))
            .filter_map(|part| part.text.as_deref())
            .collect::<Vec<_>>()
            .join("\n");

        if final_text.trim().is_empty() {
            let part_info = candidate
                .content
                .parts
                .iter()
                .map(|part| {
                    format!(
                        "thought={:?}, text_present={}",
                        part.thought,
                        part.text.is_some()
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");

            return Err(format!(
                "No final response. Finish reason: {:?}. Parts: [{}]",
                candidate.finish_reason, part_info
            ));
        }

        let json_start = final_text
            .find('{')
            .ok_or("Gemma response did not contain a JSON object")?;

        let json_end = final_text
            .rfind('}')
            .ok_or("Gemma response contained incomplete JSON")?;

        let assessment_json = &final_text[json_start..=json_end];

        let mut assessment: GemmaAssessment =
            serde_json::from_str(assessment_json).map_err(|error| {
                format!(
                    "Could not parse Gemma assessment: {}. Response: {}",
                    error, final_text
                )
            })?;

        // Enforce the documented confidence range.
        assessment.confidence = assessment.confidence.min(100);

        Ok(assessment)
    }
}
