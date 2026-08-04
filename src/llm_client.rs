//! Advisory LLM backend built on the `llm` crate.
//!
//! This module is deliberately outside the deterministic trust decision. It
//! supplies `explain` and the opt-in, tightly scoped boring-edge verifier; any
//! construction, credential, transport, or response failure leaves the diff in
//! human review.

use llm::{
    builder::{LLMBackend, LLMBuilder},
    chat::ChatMessage,
};

use crate::classifier::Llm;
use crate::config::Config;

#[derive(Debug, Clone)]
pub struct NativeLlm {
    backend: LLMBackend,
    backend_name: String,
    model: String,
    base_url: Option<String>,
    timeout_seconds: u64,
}

impl NativeLlm {
    pub fn from_config(config: &Config) -> Result<Self, String> {
        let backend = config
            .llm_backend
            .parse::<LLMBackend>()
            .map_err(|error| format!("invalid LLM backend: {error}"))?;
        Ok(Self {
            backend,
            backend_name: config.llm_backend.clone(),
            model: config.explain_model.clone(),
            base_url: config.llm_base_url.clone(),
            timeout_seconds: config.llm_timeout_seconds,
        })
    }

    pub fn description(&self) -> String {
        format!("{}:{}", self.backend_name, self.model)
    }

    fn api_key(&self) -> Option<String> {
        let provider_key = match self.backend {
            LLMBackend::OpenAI => "OPENAI_API_KEY",
            LLMBackend::Anthropic => "ANTHROPIC_API_KEY",
            LLMBackend::DeepSeek => "DEEPSEEK_API_KEY",
            LLMBackend::OpenRouter => "OPENROUTER_API_KEY",
            LLMBackend::Ollama => "OLLAMA_API_KEY",
            _ => return None,
        };
        std::env::var("AUR_GATE_LLM_API_KEY")
            .ok()
            .or_else(|| std::env::var(provider_key).ok())
            .filter(|key| !key.is_empty())
    }
}

impl Llm for NativeLlm {
    fn complete(&mut self, prompt: &str) -> Result<String, String> {
        let mut builder = LLMBuilder::new()
            .backend(self.backend.clone())
            .model(self.model.clone())
            .max_tokens(1024)
            .temperature(0.0)
            .timeout_seconds(self.timeout_seconds)
            .normalize_response(true);
        if let Some(base_url) = &self.base_url {
            builder = builder.base_url(base_url.clone());
        }
        if let Some(api_key) = self.api_key() {
            builder = builder.api_key(api_key);
        }
        let provider = builder.build().map_err(|error| {
            format!("could not configure {} backend: {error}", self.backend_name)
        })?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("could not start LLM runtime: {error}"))?;
        let messages = [ChatMessage::user().content(prompt).build()];
        let response = runtime
            .block_on(provider.chat(&messages))
            .map_err(|error| format!("LLM request failed: {error}"))?;
        response
            .text()
            .filter(|text| !text.is_empty())
            .ok_or_else(|| "LLM response contained no text".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn description_is_provider_and_model() {
        let client = NativeLlm {
            backend: LLMBackend::Ollama,
            backend_name: "ollama".into(),
            model: "qwen3:8b".into(),
            base_url: None,
            timeout_seconds: 30,
        };
        assert_eq!(client.description(), "ollama:qwen3:8b");
    }
}
