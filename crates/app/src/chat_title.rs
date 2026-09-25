//! Best-effort, model-written names for newly started work and edit chats.
//!
//! This is a separate, bounded model call. It uses the provider, model, and
//! credential selected for the turn, and never writes to the conversation or
//! changes the turn's result. The library write is a compare against the
//! system placeholder, so a person's rename always wins.

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use gaugedesk_harness::CredentialCapability;
use gaugedesk_whip_runtime::{NativeProviderDescriptor, OrganizationModelBrokerConfig};
use whipplescript_kernel::coerce_native::{
    CoerceTransport, CoerceTransportError, HttpRequest, HttpResponse,
};
use whipplescript_kernel::harness_loop::{ChatMessage, HarnessModelClient};
use whipplescript_kernel::harness_model::{
    assemble_codex_responses_sse, ModelWire, RealHarnessModelClient,
};

const MAX_TITLE_CHARS: usize = 48;
const MAX_CONTEXT_CHARS: usize = 2_000;
const MAX_RESPONSE_BYTES: u64 = 512 * 1024;
const TITLE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub(crate) struct TitleModelContext {
    pub descriptor: NativeProviderDescriptor,
    pub credential: Option<Arc<dyn CredentialCapability>>,
    pub organization_broker: Option<OrganizationModelBrokerConfig>,
    /// Recheck a personal credential before the background call: a turn's
    /// snapshot must not authorize a request after the credential was revoked.
    pub personal_selection: Option<(String, crate::account::ModelExecutionClass)>,
    pub chat_id: String,
}

pub(crate) fn is_system_title(title: &str) -> bool {
    matches!(
        title.trim().to_ascii_lowercase().as_str(),
        "" | "new chat" | "edit chat"
    )
}

/// Preserve the pre-existing first-message title as a failure fallback. No
/// second provider or credential is chosen when naming is unavailable.
pub(crate) fn fallback_title(prompt: &str) -> String {
    let one_line = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
    if one_line.is_empty() || crate::gaugeapp_agent::contains_secret_text(&one_line) {
        return "Untitled".to_owned();
    }
    if one_line.chars().count() <= MAX_TITLE_CHARS {
        return one_line;
    }
    let prefix = one_line
        .chars()
        .take(MAX_TITLE_CHARS - 1)
        .collect::<String>();
    format!("{}…", prefix.trim_end())
}

fn bounded_context(text: &str) -> String {
    text.chars().take(MAX_CONTEXT_CHARS).collect()
}

fn title_prompt(user: &str, assistant: &str) -> String {
    format!(
        "Name this private chat. Return only a concise title of two to six words, \
         at most 48 characters. Name the task or topic, not the assistant's action. \
         Do not include quotes, Markdown, a label, private identifiers, credentials, \
         or a trailing period.\n\nFirst user message:\n{}\n\nFirst assistant reply:\n{}",
        bounded_context(user),
        bounded_context(assistant)
    )
}

fn clean_title(raw: &str) -> Option<String> {
    let first = raw.lines().find(|line| !line.trim().is_empty())?.trim();
    let first = first
        .strip_prefix("Title:")
        .or_else(|| first.strip_prefix("title:"))
        .unwrap_or(first)
        .trim();
    let one_line = first.split_whitespace().collect::<Vec<_>>().join(" ");
    let title = one_line
        .trim_end_matches(['.', ':', ';'])
        .trim()
        .trim_matches(['"', '\'', '`'])
        .trim();
    if title.is_empty()
        || is_system_title(title)
        || crate::gaugeapp_agent::contains_secret_text(title)
        || title.chars().any(char::is_control)
    {
        return None;
    }
    let title = title.chars().take(MAX_TITLE_CHARS).collect::<String>();
    Some(title.trim_end().to_owned())
}

struct TitleTransport<'a> {
    broker: Option<&'a OrganizationModelBrokerConfig>,
}

/// Keep the naming call's effort independent of the chat's chosen effort.
/// Only send fields supported by a known provider/model pair: a custom
/// OpenAI-compatible endpoint may reject an OpenAI-specific reasoning field.
struct TitleEffortTransport<'a, T> {
    inner: &'a T,
    descriptor: &'a NativeProviderDescriptor,
}

impl<T: CoerceTransport> CoerceTransport for TitleEffortTransport<'_, T> {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError> {
        let mut request = request.clone();
        let model = self.descriptor.model.to_ascii_lowercase();
        match self.descriptor.provider_name.as_str() {
            // These standard GPT-5 models accept no reasoning on Responses.
            "openai-codex" | "openai" if known_standard_gpt_five(&model) => {
                request.body["reasoning"] = serde_json::json!({ "effort": "none" });
            }
            // The documented floor for the Pro variants is medium.
            "openai" if matches!(model.as_str(), "gpt-5.4-pro" | "gpt-5.5-pro") => {
                request.body["reasoning"] = serde_json::json!({ "effort": "medium" });
            }
            // The xAI title call uses Responses so these effort controls are
            // accepted there, unlike on the regular Chat Completions wire.
            "xai" if model.starts_with("grok-4.3") => {
                request.body["reasoning"] = serde_json::json!({ "effort": "none" });
            }
            "xai"
                if ["grok-4.5", "grok-4.6", "grok-4.7"]
                    .iter()
                    .any(|family| model.starts_with(family)) =>
            {
                request.body["reasoning"] = serde_json::json!({ "effort": "low" });
            }
            // Anthropic's currently shipped models run without extended
            // thinking when the field is omitted. Other endpoints and the
            // Grok subscription proxy have no verified low-effort wire here.
            _ => {}
        }
        self.inner.post(&request)
    }
}

fn known_standard_gpt_five(model: &str) -> bool {
    matches!(
        model,
        "gpt-5.4"
            | "gpt-5.4-mini"
            | "gpt-5.4-nano"
            | "gpt-5.5"
            | "gpt-5.6"
            | "gpt-5.6-sol"
            | "gpt-5.6-terra"
            | "gpt-5.6-luna"
    )
}

impl CoerceTransport for TitleTransport<'_> {
    fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError> {
        if let Some(broker) = self.broker {
            return broker.fetch_for_title(request);
        }
        let agent = ureq::AgentBuilder::new()
            .timeout(TITLE_TIMEOUT)
            .redirects(0)
            .build();
        let mut outgoing = agent.post(&request.url);
        for (name, value) in &request.headers {
            outgoing = outgoing.set(name, value);
        }
        let response = match outgoing.send_json(&request.body) {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(error)) => {
                return Err(
                    if error.to_string().to_ascii_lowercase().contains("timeout") {
                        CoerceTransportError::Timeout
                    } else {
                        CoerceTransportError::Transport("title provider unavailable".to_owned())
                    },
                );
            }
        };
        let status = response.status();
        let sse = request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("accept") && value.contains("event-stream")
        });
        let mut body = Vec::new();
        response
            .into_reader()
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut body)
            .map_err(|_| CoerceTransportError::Transport("title response unreadable".to_owned()))?;
        if body.len() as u64 > MAX_RESPONSE_BYTES {
            return Err(CoerceTransportError::Transport(
                "title response exceeded limit".to_owned(),
            ));
        }
        let parsed = if sse {
            let stream = String::from_utf8(body).map_err(|_| {
                CoerceTransportError::Transport("title response is not UTF-8".to_owned())
            })?;
            assemble_codex_responses_sse(&stream)
        } else {
            serde_json::from_slice(&body).map_err(|_| {
                CoerceTransportError::Transport("title response is not JSON".to_owned())
            })?
        };
        Ok(HttpResponse {
            status,
            body: parsed,
        })
    }
}

pub(crate) fn generate_title(
    context: &TitleModelContext,
    user: &str,
    assistant: &str,
) -> Result<String, String> {
    let transport = TitleTransport {
        broker: context.organization_broker.as_ref(),
    };
    generate_title_with_transport(context, user, assistant, &transport)
}

fn generate_title_with_transport<T: CoerceTransport>(
    context: &TitleModelContext,
    user: &str,
    assistant: &str,
    transport: &T,
) -> Result<String, String> {
    let capability = context
        .credential
        .as_ref()
        .ok_or_else(|| "no title model credential".to_owned())?;
    let material = capability
        .resolve(capability.credential_ref())
        .map_err(|_| "title model credential unavailable".to_owned())?;
    let descriptor = &context.descriptor;
    let title_transport = TitleEffortTransport {
        inner: transport,
        descriptor,
    };
    let cache_key = Some(format!("gaugedesk-title:{}", context.chat_id));
    let messages = [ChatMessage::user_text(title_prompt(user, assistant))];
    let model: Box<dyn HarnessModelClient + '_> = match descriptor.provider_name.as_str() {
        "openai-codex" => Box::new(RealHarnessModelClient::new_codex(
            &title_transport,
            material.secret(),
            material
                .account_id()
                .ok_or("Codex account id unavailable")?,
            format!("title-{}", context.chat_id),
            &descriptor.model,
            &descriptor.base_url,
            Some(256),
            cache_key,
        )),
        // xAI exposes reasoning effort on Responses, while regular turns use
        // its Chat Completions wire. The title call has no tools and can use
        // Responses without changing the turn's provider or credential.
        "xai" => Box::new(RealHarnessModelClient::new(
            &title_transport,
            ModelWire::OpenAiResponses,
            material.secret(),
            &descriptor.model,
            &descriptor.base_url,
            Some(256),
            None,
        )),
        "xai-grok" => Box::new(RealHarnessModelClient::new_xai_subscription(
            &title_transport,
            material.secret(),
            &descriptor.model,
            &descriptor.base_url,
            Some(256),
            cache_key,
        )),
        _ => Box::new(RealHarnessModelClient::new(
            &title_transport,
            ModelWire::parse(descriptor.wire).ok_or("unsupported title model wire")?,
            material.secret(),
            &descriptor.model,
            &descriptor.base_url,
            Some(256),
            cache_key,
        )),
    };
    let reply = model
        .next(&messages, &[])
        .map_err(|_| "title model call failed".to_owned())?;
    clean_title(&reply.text).ok_or_else(|| "title model returned no usable title".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    struct FakeTransport(Mutex<Vec<HttpRequest>>);

    impl CoerceTransport for FakeTransport {
        fn post(&self, request: &HttpRequest) -> Result<HttpResponse, CoerceTransportError> {
            self.0.lock().unwrap().push(request.clone());
            Ok(HttpResponse {
                status: 200,
                body: serde_json::json!({
                    "output_text": "Fix login expiry",
                    "usage": { "input_tokens": 20, "output_tokens": 5 }
                }),
            })
        }
    }

    #[test]
    fn names_from_the_selected_model_without_writing_into_the_chat() {
        let transport = FakeTransport(Mutex::new(Vec::new()));
        let context = TitleModelContext {
            descriptor: gaugedesk_whip_runtime::native_provider_descriptor(
                "openai",
                Some("gpt-5.5"),
                None,
            )
            .unwrap(),
            credential: Some(crate::account::resolved_credential_capability(
                "credential-1".into(),
                "synthetic-key".into(),
                None,
            )),
            organization_broker: None,
            personal_selection: None,
            chat_id: "chat-1".into(),
        };
        let title = generate_title_with_transport(
            &context,
            "Please fix the login expiry bug",
            "I found the timer mismatch and corrected it.",
            &transport,
        )
        .unwrap();
        assert_eq!(title, "Fix login expiry");
        let requests = transport.0.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].url.ends_with("/v1/responses"));
        let body = requests[0].body.to_string();
        assert!(body.contains("Please fix the login expiry bug"));
        assert!(body.contains("timer mismatch"));
        assert_eq!(requests[0].body["reasoning"]["effort"], "none");
    }

    #[test]
    fn title_effort_uses_each_known_models_lowest_request_setting() {
        for (provider, model, expected) in [
            ("openai-codex", "gpt-5.5", "none"),
            ("openai", "gpt-5.4-mini", "none"),
            ("openai", "gpt-5.4-pro", "medium"),
            ("openai", "gpt-5.5-pro", "medium"),
            ("openai", "gpt-5.6-sol", "none"),
            ("xai", "grok-4.3", "none"),
            ("xai", "grok-4.6", "low"),
        ] {
            let descriptor =
                gaugedesk_whip_runtime::native_provider_descriptor(provider, Some(model), None)
                    .unwrap();
            let inner = FakeTransport(Mutex::new(Vec::new()));
            let transport = TitleEffortTransport {
                inner: &inner,
                descriptor: &descriptor,
            };
            transport
                .post(&HttpRequest {
                    url: "https://example.test".into(),
                    headers: Vec::new(),
                    body: serde_json::json!({ "model": model }),
                })
                .unwrap();
            let requests = inner.0.lock().unwrap();
            assert_eq!(
                requests[0].body["reasoning"]["effort"], expected,
                "{provider}/{model}"
            );
        }
    }

    #[test]
    fn xai_title_call_uses_responses_for_low_reasoning() {
        let transport = FakeTransport(Mutex::new(Vec::new()));
        let context = TitleModelContext {
            descriptor: gaugedesk_whip_runtime::native_provider_descriptor(
                "xai",
                Some("grok-4.6"),
                None,
            )
            .unwrap(),
            credential: Some(crate::account::resolved_credential_capability(
                "credential-1".into(),
                "synthetic-key".into(),
                None,
            )),
            organization_broker: None,
            personal_selection: None,
            chat_id: "chat-1".into(),
        };
        assert_eq!(
            generate_title_with_transport(&context, "Fix login", "Done", &transport).unwrap(),
            "Fix login expiry"
        );
        let requests = transport.0.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].url.ends_with("/v1/responses"));
        assert_eq!(requests[0].body["reasoning"]["effort"], "low");
        assert!(requests[0].body.get("prompt_cache_key").is_none());
    }

    #[test]
    fn unknown_endpoint_does_not_get_an_unsupported_reasoning_field() {
        let descriptor = gaugedesk_whip_runtime::native_provider_descriptor(
            "openai-generic",
            Some("custom-model"),
            Some("https://model.example/v1"),
        )
        .unwrap();
        let inner = FakeTransport(Mutex::new(Vec::new()));
        let transport = TitleEffortTransport {
            inner: &inner,
            descriptor: &descriptor,
        };
        transport
            .post(&HttpRequest {
                url: "https://model.example/v1/chat/completions".into(),
                headers: Vec::new(),
                body: serde_json::json!({ "model": "custom-model" }),
            })
            .unwrap();
        assert_eq!(
            inner.0.lock().unwrap()[0].body,
            serde_json::json!({ "model": "custom-model" })
        );
    }

    #[test]
    fn keeps_a_short_model_title_and_strips_formatting() {
        assert_eq!(
            clean_title("Title: \"Fix login expiry\"."),
            Some("Fix login expiry".into())
        );
        assert_eq!(
            clean_title("  Improve onboarding flow  "),
            Some("Improve onboarding flow".into())
        );
    }

    #[test]
    fn refuses_placeholder_and_secret_like_output() {
        assert_eq!(clean_title("new chat"), None);
        assert_eq!(clean_title("sk-live-abcdefghijklmnop"), None);
    }

    #[test]
    fn failure_fallback_is_the_existing_first_message_title() {
        assert_eq!(fallback_title("  draft   a\n tagline "), "draft a tagline");
        assert_eq!(
            fallback_title(&"a".repeat(60)),
            format!("{}…", "a".repeat(47))
        );
    }
}
