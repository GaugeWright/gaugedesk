//! The Pi RPC wire protocol (Pi 0.73.1, `badlogic/pi-mono`): JSON lines on
//! stdin (commands) and stdout (responses + a streamed `AgentSessionEvent`
//! stream). We model only the subset the MVP adapter drives; everything else
//! is `Other` and ignored. See `specs/implementation/pi-rpc.md`.

use serde::{Deserialize, Serialize};

/// The image content block lives in `gaugedesk-harness` (SUB-0); re-exported at
/// its pre-extraction path so existing callers keep compiling unchanged.
pub use gaugedesk_harness::{ImageContent, ImageKind};

/// A command we send to Pi as one JSON line on stdin.
#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum Command {
    /// A turn over the engagement's persistent Pi thread. `images` carries native
    /// image content blocks for this turn (empty for a plain text turn); Pi accepts
    /// `{ type:"prompt", message, images }` over RPC.
    #[serde(rename = "prompt")]
    Prompt {
        message: String,
        images: Vec<ImageContent>,
    },
    /// Interrupt the in-flight turn (a runtime-session attempt's abort).
    #[serde(rename = "abort")]
    Abort,
    /// Fetch the turn's final assistant text after `agent_end`.
    #[serde(rename = "get_last_assistant_text")]
    GetLastAssistantText,
}

impl Command {
    pub fn to_line(&self) -> String {
        // serde_json never fails on these owned, finite values.
        serde_json::to_string(self).expect("serialize Pi command")
    }
}

/// One line from Pi's stdout: either a streamed session event or a response to a
/// command. Unknown `type`s parse to `Other` so the stream stays forward-compatible.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum Line {
    #[serde(rename = "agent_start")]
    AgentStart,
    #[serde(rename = "turn_start")]
    TurnStart,
    #[serde(rename = "turn_end")]
    TurnEnd,
    /// A top-level text delta (some event shapes carry it directly).
    #[serde(rename = "text_delta")]
    TextDelta { delta: String },
    /// The assistant's streamed message. The token delta is **nested** under
    /// `assistantMessageEvent` (Pi wraps each streaming chunk this way).
    #[serde(rename = "message_update")]
    MessageUpdate {
        #[serde(rename = "assistantMessageEvent", default)]
        assistant_message_event: Option<AssistantMessageEvent>,
    },
    /// An external effect: a tool the agent is about to execute. `args` carries
    /// the call's parameters (file path, command, …); `tool_target` distils the
    /// one that names what the tool acts on — the B4 tool line's clickable target.
    #[serde(rename = "tool_execution_start")]
    ToolExecutionStart {
        #[serde(rename = "toolName")]
        tool_name: String,
        #[serde(rename = "toolCallId", default)]
        call_id: String,
        #[serde(default)]
        args: serde_json::Value,
    },
    /// A tool finished. `isError` carries the ✓/✗; `result` the (truncated) output.
    #[serde(rename = "tool_execution_end")]
    ToolExecutionEnd {
        #[serde(rename = "toolCallId", default)]
        call_id: String,
        #[serde(default)]
        result: serde_json::Value,
        #[serde(rename = "isError", default)]
        is_error: bool,
    },
    /// The turn is complete. The subprocess persists for the next turn.
    #[serde(rename = "agent_end")]
    AgentEnd,
    #[serde(rename = "error")]
    Error {
        #[serde(default)]
        error: Option<String>,
    },
    /// A response to a command (`get_last_assistant_text`, etc.).
    #[serde(rename = "response")]
    Response {
        command: String,
        success: bool,
        #[serde(default)]
        data: serde_json::Value,
        #[serde(default)]
        error: Option<String>,
    },
    /// An extension UI request (in-run approval prompt, A5b). Surfaced, not auto-answered.
    #[serde(rename = "extension_ui_request")]
    ExtensionUiRequest {
        id: String,
        method: String,
        #[serde(default)]
        title: String,
    },
    #[serde(other)]
    Other,
}

impl Line {
    pub fn parse(s: &str) -> Result<Line, serde_json::Error> {
        serde_json::from_str(s)
    }
}

/// The one argument that names what a tool acts on — the file it reads/edits, the
/// command it runs, the URL it fetches. This is the B4 tool line's clickable
/// **target** (`run-chat.md`). We probe the conventional Pi tool-arg keys in
/// priority order and fall back to none rather than guess.
pub fn tool_target(args: &serde_json::Value) -> Option<String> {
    const KEYS: &[&str] = &[
        "path",
        "file_path",
        "filePath",
        "command",
        "url",
        "pattern",
        "query",
    ];
    KEYS.iter()
        .find_map(|k| args.get(k).and_then(|v| v.as_str()))
        .map(str::to_string)
}

/// A short, single-line digest of a tool result for the collapsed/expanded line.
/// Strings pass through (truncated); structured results render compactly.
pub fn result_summary(result: &serde_json::Value) -> Option<String> {
    let text = match result {
        serde_json::Value::Null => return None,
        serde_json::Value::String(s) => s.clone(),
        // Pi tool results arrive structured as `{ content: [ { type: "text",
        // text: "…" }, … ] }`. Extract and join the text parts so the expanded
        // line shows the tool's actual output, not a JSON blob. Fall back to a
        // compact JSON rendering for shapes that carry no text content.
        v => content_text(v).unwrap_or_else(|| v.to_string()),
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    const MAX: usize = 2000;
    Some(if trimmed.chars().count() > MAX {
        format!("{}…", trimmed.chars().take(MAX).collect::<String>())
    } else {
        trimmed.to_string()
    })
}

/// Join the `text` parts of a Pi structured result/content payload
/// (`{ content: [ { type: "text", text: "…" } ] }`). `None` if the shape carries
/// no `content` array or no text parts.
fn content_text(v: &serde_json::Value) -> Option<String> {
    let parts = v.get("content")?.as_array()?;
    let joined: String = parts
        .iter()
        .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
        .collect();
    (!joined.is_empty()).then_some(joined)
}

/// The inner streaming event Pi nests inside a `message_update`. We only need
/// the text delta; other shapes (`text_start`, `text_end`, …) carry no `delta`.
#[derive(Debug, Clone, Deserialize)]
pub struct AssistantMessageEvent {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub delta: Option<String>,
}

pub mod remote;

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact `tool_execution_start`/`end` lines a live Pi (0.73.x) emits for a
    /// bash call — captured from the running agent. Locks the parse + distillation
    /// against Pi's real schema (args object; result nested as `{content:[{text}]}`).
    #[test]
    fn real_pi_tool_schema_yields_target_and_clean_result() {
        let start = r#"{"type":"tool_execution_start","toolCallId":"call_X|fc_Y","toolName":"bash","args":{"command":"echo hello-probe"}}"#;
        let Line::ToolExecutionStart {
            tool_name,
            call_id,
            args,
        } = Line::parse(start).unwrap()
        else {
            panic!("expected ToolExecutionStart");
        };
        assert_eq!(tool_name, "bash");
        assert_eq!(call_id, "call_X|fc_Y");
        // the clickable target is distilled from the call's command arg
        assert_eq!(tool_target(&args).as_deref(), Some("echo hello-probe"));
        // args survive as compact JSON for the expanded view
        assert_eq!(args.to_string(), r#"{"command":"echo hello-probe"}"#);

        let end = r#"{"type":"tool_execution_end","toolCallId":"call_X|fc_Y","result":{"content":[{"type":"text","text":"hello-probe\n"}]},"isError":false}"#;
        let Line::ToolExecutionEnd {
            result, is_error, ..
        } = Line::parse(end).unwrap()
        else {
            panic!("expected ToolExecutionEnd");
        };
        assert!(!is_error);
        // the nested {content:[{text}]} shape distils to the tool's actual output —
        // NOT a raw JSON blob (the bug this guards).
        assert_eq!(result_summary(&result).as_deref(), Some("hello-probe"));
    }

    #[test]
    fn prompt_command_serializes_to_pis_exact_shape_with_images() {
        let cmd = Command::Prompt {
            message: "look at this".into(),
            images: vec![ImageContent {
                kind: ImageKind::Image,
                data: "QUJD".into(),
                mime_type: "image/png".into(),
            }],
        };
        assert_eq!(
            cmd.to_line(),
            r#"{"type":"prompt","message":"look at this","images":[{"type":"image","data":"QUJD","mimeType":"image/png"}]}"#
        );
    }

    #[test]
    fn a_plain_text_turn_sends_an_empty_images_array() {
        let cmd = Command::Prompt {
            message: "hi".into(),
            images: vec![],
        };
        assert_eq!(
            cmd.to_line(),
            r#"{"type":"prompt","message":"hi","images":[]}"#
        );
    }

    #[test]
    fn image_content_deserializes_from_the_web_body_without_a_type_tag() {
        // The web client sends `{ data, mimeType }`; the `type` tag defaults in.
        let img: ImageContent =
            serde_json::from_str(r#"{"data":"QUJD","mimeType":"image/jpeg"}"#).unwrap();
        assert_eq!(img.kind, ImageKind::Image);
        assert_eq!(img.mime_type, "image/jpeg");
        assert_eq!(img.data, "QUJD");
    }

    #[test]
    fn result_summary_falls_back_to_json_when_no_text_content() {
        let v: serde_json::Value = serde_json::json!({ "exit": 0, "details": {} });
        assert_eq!(
            result_summary(&v).as_deref(),
            Some(r#"{"details":{},"exit":0}"#)
        );
        assert_eq!(result_summary(&serde_json::Value::Null), None);
        assert_eq!(
            result_summary(&serde_json::json!("plain string")).as_deref(),
            Some("plain string")
        );
    }
}
