use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use gaugewright_app::agent_release::{
    AcknowledgeCollectionsRequest, ControlDeploymentRequest, DrainCollectionsRequest,
    ErasePublicSessionRequest, ListPublicCredentialsRequest, ProvisionPublicCredentialRequest,
    PublishDeploymentRequest, ReleasePublishSpec, RevokePublicCredentialRequest,
};
use gaugewright_app::{open_workbench, LockUnpoisoned, Workbench};
use gaugewright_core::agent_release::{
    AttributionPolicy, PanelManifest, ProviderPolicy, RetentionPolicy, SignedAgentRelease,
    AGENT_RELEASE_MEDIA_TYPE,
};

fn usage() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "usage:\n  \
         gaugedesk-agent-release build <workbench-root> <placement-id> <output.cbor> [model]\n  \
         gaugedesk-agent-release publish <workbench-root> <placement-id> <edge-origin> \
           <deployment-id> <config.json> [model]\n  \
         gaugedesk-agent-release publish-request <workbench-root> <request.json>\n  \
         gaugedesk-agent-release update <workbench-root> <placement-id> <edge-origin> \
           <deployment-id> <expected-release-id> [model]\n  \
         gaugedesk-agent-release release-inspect <workbench-root> <edge-origin> <release-id>\n  \
         gaugedesk-agent-release inspect <workbench-root> <edge-origin> <deployment-id>\n  \
         gaugedesk-agent-release control <workbench-root> <edge-origin> <deployment-id> \
           <pause|resume|revoke> <expected-revision>\n  \
         gaugedesk-agent-release erase-session <workbench-root> <edge-origin> <deployment-id> \
           <session-id>\n  \
         gaugedesk-agent-release credential-list <workbench-root> <edge-origin>\n  \
         gaugedesk-agent-release credential-provision <workbench-root> <request.json>\n  \
         gaugedesk-agent-release credential-revoke <workbench-root> <request.json>\n  \
         gaugedesk-agent-release collection-recipient <workbench-root> <recipient-id>\n  \
         gaugedesk-agent-release collections-drain <workbench-root> <request.json>\n  \
         gaugedesk-agent-release collections-acknowledge <workbench-root> <request.json>",
    )
}

fn main() -> io::Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("build") => {
            let root = path_arg(args.next())?;
            let placement = string_arg(args.next())?;
            let output = path_arg(args.next())?;
            let model = args.next().unwrap_or_else(default_model);
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            let release = build_release(&workbench.lock_unpoisoned(), &placement, model)?;
            fs::write(
                &output,
                release.canonical_bytes().map_err(io::Error::other)?,
            )?;
            println!("{}", release.release_id());
        }
        Some("publish") => {
            let root = path_arg(args.next())?;
            let placement = string_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let deployment = deployment_arg(args.next())?;
            let config_path = path_arg(args.next())?;
            let model = args.next().unwrap_or_else(default_model);
            no_more(args)?;
            let config: serde_json::Value =
                serde_json::from_slice(&fs::read(config_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            let workbench = workbench.lock_unpoisoned();
            let release = build_release(&workbench, &placement, model)?;
            upload_release(&workbench, &edge, &release)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "config": config,
                "initial_release_id": release.release_id(),
            }))
            .map_err(invalid)?;
            let path = format!("/v1/deployments/{deployment}");
            let response = send(&workbench, &edge, "PUT", &path, &body, "application/json")?;
            println!("{response}");
            eprintln!(
                "embed: <gw-session deployment=\"{deployment}\" edge=\"{}\"></gw-session>",
                normalized_edge(&edge)?,
            );
        }
        Some("publish-request") => {
            let root = path_arg(args.next())?;
            let request_path = path_arg(args.next())?;
            no_more(args)?;
            let request: PublishDeploymentRequest =
                serde_json::from_slice(&fs::read(request_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            let outcome = workbench
                .lock_unpoisoned()
                .publish_agent_deployment(request)?;
            println!("{}", serde_json::to_string(&outcome).map_err(invalid)?);
        }
        Some("update") => {
            let root = path_arg(args.next())?;
            let placement = string_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let deployment = deployment_arg(args.next())?;
            let expected_release_id = release_arg(args.next())?;
            let model = args.next().unwrap_or_else(default_model);
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            let workbench = workbench.lock_unpoisoned();
            let release = build_release(&workbench, &placement, model)?;
            upload_release(&workbench, &edge, &release)?;
            let body = serde_json::to_vec(&serde_json::json!({
                "expected_release_id": expected_release_id,
                "release_id": release.release_id(),
            }))
            .map_err(invalid)?;
            let path = format!("/v1/deployments/{deployment}/activate");
            println!(
                "{}",
                send(&workbench, &edge, "POST", &path, &body, "application/json")?,
            );
        }
        Some("inspect") => {
            let root = path_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let deployment = deployment_arg(args.next())?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                send(
                    &workbench.lock_unpoisoned(),
                    &edge,
                    "GET",
                    &format!("/v1/deployments/{deployment}"),
                    &[],
                    "application/octet-stream",
                )?,
            );
        }
        Some("release-inspect") => {
            let root = path_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let release = release_arg(args.next())?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                send(
                    &workbench.lock_unpoisoned(),
                    &edge,
                    "GET",
                    &format!("/v1/releases/{release}"),
                    &[],
                    "application/octet-stream",
                )?,
            );
        }
        Some("control") => {
            let root = path_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let deployment = deployment_arg(args.next())?;
            let command = string_arg(args.next())?;
            let expected_revision = string_arg(args.next())?.parse::<u64>().map_err(invalid)?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench.lock_unpoisoned().control_public_deployment(
                    ControlDeploymentRequest {
                        deployment_id: deployment,
                        edge_origin: edge,
                        command,
                        expected_revision,
                    },
                )?,
            );
        }
        Some("erase-session") => {
            let root = path_arg(args.next())?;
            let edge = string_arg(args.next())?;
            let deployment = deployment_arg(args.next())?;
            let session_id = string_arg(args.next())?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench
                    .lock_unpoisoned()
                    .erase_public_session(ErasePublicSessionRequest {
                        deployment_id: deployment,
                        edge_origin: edge,
                        session_id,
                    },)?,
            );
        }
        Some("credential-list") => {
            let root = path_arg(args.next())?;
            let edge_origin = string_arg(args.next())?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench
                    .lock_unpoisoned()
                    .list_public_credentials(ListPublicCredentialsRequest { edge_origin },)?,
            );
        }
        Some("credential-provision") => {
            let root = path_arg(args.next())?;
            let request_path = path_arg(args.next())?;
            no_more(args)?;
            let request: ProvisionPublicCredentialRequest =
                serde_json::from_slice(&fs::read(request_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench
                    .lock_unpoisoned()
                    .provision_public_credential(request)?,
            );
        }
        Some("credential-revoke") => {
            let root = path_arg(args.next())?;
            let request_path = path_arg(args.next())?;
            no_more(args)?;
            let request: RevokePublicCredentialRequest =
                serde_json::from_slice(&fs::read(request_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench
                    .lock_unpoisoned()
                    .revoke_public_credential(request)?,
            );
        }
        Some("collection-recipient") => {
            let root = path_arg(args.next())?;
            let recipient_id = string_arg(args.next())?;
            no_more(args)?;
            let workbench = open_workbench(&root)?;
            let recipient = workbench
                .lock_unpoisoned()
                .ensure_collection_recipient(&recipient_id)?;
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "recipient_ref": recipient.recipient_ref,
                    "public_key_hex": recipient.public_key_hex,
                }))
                .map_err(invalid)?,
            );
        }
        Some("collections-drain") => {
            let root = path_arg(args.next())?;
            let request_path = path_arg(args.next())?;
            no_more(args)?;
            let request: DrainCollectionsRequest =
                serde_json::from_slice(&fs::read(request_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench.lock_unpoisoned().drain_collections(request)?,
            );
        }
        Some("collections-acknowledge") => {
            let root = path_arg(args.next())?;
            let request_path = path_arg(args.next())?;
            no_more(args)?;
            let request: AcknowledgeCollectionsRequest =
                serde_json::from_slice(&fs::read(request_path)?).map_err(invalid)?;
            let workbench = open_workbench(&root)?;
            println!(
                "{}",
                workbench
                    .lock_unpoisoned()
                    .acknowledge_collections(request)?,
            );
        }
        _ => return Err(usage()),
    }
    Ok(())
}

fn build_release(
    workbench: &Workbench,
    placement: &str,
    model: String,
) -> io::Result<SignedAgentRelease> {
    let published_at_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_millis()
        .try_into()
        .map_err(io::Error::other)?;
    workbench.build_agent_release(
        placement,
        ReleasePublishSpec {
            published_at_unix_ms,
            panels: PanelManifest {
                components: BTreeSet::from([
                    "gw-chat".to_owned(),
                    "gw-viewer".to_owned(),
                    "gw-files".to_owned(),
                    "gw-chats".to_owned(),
                ]),
                default_component: "gw-chat".to_owned(),
                attribution: AttributionPolicy::GaugeWright,
            },
            provider: ProviderPolicy {
                provider: "openai".to_owned(),
                model,
                base_url: "https://api.openai.com".to_owned(),
                credential_class: "managed-openai".to_owned(),
                max_input_tokens: 100_000,
                max_output_tokens: 8_000,
            },
            retention: RetentionPolicy {
                idle_ttl_seconds: 86_400,
                absolute_ttl_seconds: 2_592_000,
                transcript_retained: true,
                workspace_retained: true,
            },
            initial_workspace: Vec::new(),
            collection: None,
        },
    )
}

fn upload_release(
    workbench: &Workbench,
    edge: &str,
    release: &SignedAgentRelease,
) -> io::Result<()> {
    let body = release.canonical_bytes().map_err(io::Error::other)?;
    send(
        workbench,
        edge,
        "PUT",
        &format!("/v1/releases/{}", release.release_id()),
        &body,
        AGENT_RELEASE_MEDIA_TYPE,
    )?;
    Ok(())
}

fn send(
    workbench: &Workbench,
    edge: &str,
    method: &str,
    path: &str,
    body: &[u8],
    content_type: &str,
) -> io::Result<String> {
    let authorization = workbench.authorize_publisher_command(method, path, body)?;
    let request = authorization
        .apply(ureq::request(
            method,
            &format!("{}{path}", normalized_edge(edge)?),
        ))
        .set("content-type", content_type);
    let result = if body.is_empty() {
        request.call()
    } else {
        request.send_bytes(body)
    };
    match result {
        Ok(response) => response.into_string().map_err(io::Error::other),
        Err(ureq::Error::Status(status, response)) => {
            let detail = response
                .into_string()
                .unwrap_or_else(|_| "hosted publisher command failed".to_owned());
            Err(io::Error::other(format!(
                "edge publisher rejected command ({status}): {detail}"
            )))
        }
        Err(error) => Err(io::Error::other(error)),
    }
}

fn normalized_edge(value: &str) -> io::Result<String> {
    let edge = value.trim().trim_end_matches('/');
    if (!edge.starts_with("https://")
        && !edge.starts_with("http://127.0.0.1:")
        && !edge.starts_with("http://localhost:"))
        || edge.contains('?')
        || edge.contains('#')
    {
        return Err(invalid("edge origin must be HTTPS (or loopback for tests)"));
    }
    Ok(edge.to_owned())
}

fn deployment_arg(value: Option<String>) -> io::Result<String> {
    let value = string_arg(value)?;
    if value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(invalid("deployment id is invalid"));
    }
    Ok(value)
}

fn release_arg(value: Option<String>) -> io::Result<String> {
    let value = string_arg(value)?;
    if value.len() != 71
        || !value.starts_with("sha256:")
        || !value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("release id is invalid"));
    }
    Ok(value)
}

fn string_arg(value: Option<String>) -> io::Result<String> {
    value.filter(|value| !value.is_empty()).ok_or_else(usage)
}

fn path_arg(value: Option<String>) -> io::Result<PathBuf> {
    string_arg(value).map(PathBuf::from)
}

fn no_more(mut args: impl Iterator<Item = String>) -> io::Result<()> {
    if args.next().is_some() {
        return Err(usage());
    }
    Ok(())
}

fn default_model() -> String {
    "gpt-5.5".to_owned()
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, error.to_string())
}
