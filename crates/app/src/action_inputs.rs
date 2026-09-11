//! Native action-input custody and reference publication (ACTION-3).
//! The owning host admits access before calling this adapter. References are
//! data, not grants; no route, actor factory or effect dispatcher is activated
//! here. WhippleScript owns content identity, durability and publication exclusion.

use std::path::Path;

use gaugedesk_whip_runtime::host_actions::action::ActionInput;
use serde::{Deserialize, Serialize};
use whipplescript_store::content::{verify_body, ContentBlobs, ContentStore};
use whipplescript_store::{StoreError, StoreResult};

const INPUT_PROTOCOL: &str = "gaugedesk.action-input.v1";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetainedInput {
    protocol: String,
    authority_scope: String,
    handle: String,
    label_ref: String,
    content: String,
}

/// Materialized only for an already authorized operation. The byte hash is
/// distinct from the command's version, which also binds custody and labeling.
pub struct ResolvedActionInput {
    pub content: String,
    pub content_hash: String,
}

/// A dedicated input authority. Do not point it at a workspace content store:
/// that store's collector does not own product-action input roots. It inherits
/// its backend's at-rest posture; this wrapper adds no encryption guarantee.
pub struct ActionInputCustody<C> {
    content: C,
    authority_scope: String,
    byte_limit: usize,
}

pub type NativeActionInputCustody = ActionInputCustody<ContentStore>;

fn invalid(reason: &'static str) -> StoreError {
    StoreError::Conflict(reason.into())
}

impl NativeActionInputCustody {
    /// `path` and `authority_scope` come from trusted Home configuration. The
    /// same backing authority is shared by every native action in that Home:
    /// its exclusion is also their first lock, ahead of product/target writes.
    /// The caller chooses a byte budget before admitting preparation; no default
    /// budget or public/raw content endpoint is supplied by this adapter.
    pub fn open(
        path: impl AsRef<Path>,
        authority_scope: &str,
        byte_limit: usize,
    ) -> StoreResult<Self> {
        if authority_scope.trim().is_empty() {
            return Err(invalid("action input custody has no authority scope"));
        }
        Self::new(ContentStore::open(path)?, authority_scope, byte_limit)
    }
}

impl<C: ContentBlobs> ActionInputCustody<C> {
    /// Trusted custody configuration, for matching the factory's owning Home.
    pub fn authority_scope(&self) -> &str {
        &self.authority_scope
    }

    pub fn new(content: C, authority_scope: &str, byte_limit: usize) -> StoreResult<Self> {
        if authority_scope.trim().is_empty() {
            return Err(invalid("action input custody has no authority scope"));
        }
        Ok(Self {
            content,
            authority_scope: authority_scope.into(),
            byte_limit,
        })
    }

    /// Prepare exact bytes under host-derived input identity and label. Failed
    /// or abandoned admission may leave unreferenced preparation; it cannot be
    /// reported as admitted work. A future collector must own these references.
    pub fn prepare(
        &self,
        handle: &str,
        label_ref: &str,
        content: &str,
    ) -> StoreResult<ActionInput> {
        if handle.trim().is_empty() || label_ref.trim().is_empty() {
            return Err(invalid("action input has incomplete binding"));
        }
        if content.len() > self.byte_limit {
            return Err(invalid("action input exceeds the admitted byte budget"));
        }
        let retained = RetainedInput {
            protocol: INPUT_PROTOCOL.into(),
            authority_scope: self.authority_scope.clone(),
            handle: handle.into(),
            label_ref: label_ref.into(),
            content: content.into(),
        };
        let encoded = serde_json::to_string(&retained)
            .map_err(|_| invalid("action input encoding failed"))?;
        let version_ref = self.content.put_text(&encoded)?;
        Ok(ActionInput {
            handle: handle.into(),
            version_ref,
            label_ref: label_ref.into(),
        })
    }

    /// Resolve only a reference taken from an authenticated/admitted command.
    /// The stored binding is checked in addition to the backend's byte hash;
    /// possession of a hash cannot relabel it or transfer it between Homes.
    pub fn resolve(&self, reference: &ActionInput) -> StoreResult<ResolvedActionInput> {
        if reference.handle.trim().is_empty()
            || reference.label_ref.trim().is_empty()
            || reference.version_ref.trim().is_empty()
        {
            return Err(invalid("action input has incomplete binding"));
        }
        let encoded = self
            .content
            .get(&reference.version_ref)?
            .ok_or_else(|| invalid("retained action input is unavailable"))?;
        verify_body(&reference.version_ref, &encoded, "action input authority")?;
        let retained: RetainedInput = serde_json::from_slice(&encoded)
            .map_err(|_| invalid("retained action input encoding is invalid"))?;
        if retained.protocol != INPUT_PROTOCOL
            || retained.authority_scope != self.authority_scope
            || retained.handle != reference.handle
            || retained.label_ref != reference.label_ref
        {
            return Err(invalid("retained action input does not match its binding"));
        }
        if retained.content.len() > self.byte_limit {
            return Err(invalid("action input exceeds the admitted byte budget"));
        }
        Ok(ResolvedActionInput {
            content_hash: whipplescript_store::stable_hash_hex(&retained.content),
            content: retained.content,
        })
    }

    /// Resolve an admitted input under collection/erasure exclusion for a bounded
    /// native governed operation. The caller holds current product authority;
    /// the operation must use a different store for its target/evidence writes.
    /// No raw input or authority grant may escape this callback into later work.
    pub fn with_resolved<T>(
        &self,
        reference: &ActionInput,
        operation: impl FnOnce(ResolvedActionInput) -> StoreResult<T>,
    ) -> StoreResult<T> {
        self.content
            .publish_retained(std::slice::from_ref(&reference.version_ref), || {
                operation(self.resolve(reference)?)
            })
    }

    /// Hold the owner's collection/erasure exclusion while publishing references
    /// to the product log. The callback may publish references only: no payload
    /// preparation, materialization or external work. Its failure does not undo
    /// a product commit that already happened; retry must inspect that receipt.
    pub fn publish<T>(
        &self,
        references: &[ActionInput],
        publish: impl FnOnce() -> StoreResult<T>,
    ) -> StoreResult<T> {
        if references.is_empty() {
            return Err(invalid("action input publication has no references"));
        }
        let ids = references
            .iter()
            .map(|input| input.version_ref.clone())
            .collect::<Vec<_>>();
        self.content.publish_retained(&ids, || {
            for reference in references {
                self.resolve(reference)?;
            }
            publish()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gaugedesk_core::Lifecycle;
    use gaugedesk_store::{command_dispatch::CommandDispatch, Store};
    use gaugedesk_whip_runtime::host_actions::ProductActionAdmission;
    use std::cell::Cell;

    #[test]
    fn native_operation_holds_input_exclusion_and_refuses_erased_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inputs.sqlite");
        let custody = NativeActionInputCustody::open(&path, "home", 4096).unwrap();
        let input = custody
            .prepare("input", "private", "retained draft")
            .unwrap();
        let contender = rusqlite::Connection::open(&path).unwrap();
        contender.busy_timeout(std::time::Duration::ZERO).unwrap();
        let called = Cell::new(false);
        let result = custody.with_resolved(&input, |resolved| {
            assert!(contender.execute_batch("BEGIN IMMEDIATE").is_err());
            assert_eq!(resolved.content, "retained draft");
            assert_ne!(resolved.content_hash, input.version_ref);
            called.set(true);
            Err::<(), _>(invalid("lost operation response"))
        });
        assert!(result.is_err());
        assert!(called.get());
        contender
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        ContentStore::open(&path)
            .unwrap()
            .erase(&input.version_ref, "erase")
            .unwrap();
        assert!(custody
            .with_resolved::<()>(&input, |_| panic!("erased input reached operation"))
            .is_err());
    }

    #[test]
    fn retained_input_binds_scope_handle_label_and_exact_bytes_across_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inputs.sqlite");
        let custody = NativeActionInputCustody::open(&path, "home:one", 32).unwrap();
        let reference = custody
            .prepare("admitted_input", "private", "exact\nbytes")
            .unwrap();
        assert_eq!(
            custody
                .prepare("admitted_input", "private", "exact\nbytes")
                .unwrap(),
            reference
        );
        let differently_labeled = custody
            .prepare("admitted_input", "other", "exact\nbytes")
            .unwrap();
        assert_ne!(reference.version_ref, differently_labeled.version_ref);
        drop(custody);
        let custody = NativeActionInputCustody::open(&path, "home:one", 32).unwrap();
        let resolved = custody.resolve(&reference).unwrap();
        assert_eq!(resolved.content, "exact\nbytes");
        assert_eq!(
            resolved.content_hash,
            whipplescript_store::stable_hash_hex("exact\nbytes")
        );
        assert_ne!(resolved.content_hash, reference.version_ref);
        for changed in [
            ActionInput {
                label_ref: "other".into(),
                ..reference.clone()
            },
            ActionInput {
                handle: "other".into(),
                ..reference.clone()
            },
            ActionInput {
                version_ref: "missing".into(),
                ..reference.clone()
            },
        ] {
            assert!(custody.resolve(&changed).is_err());
            let calls = Cell::new(0);
            assert!(custody
                .publish(&[changed], || {
                    calls.set(1);
                    Ok(())
                })
                .is_err());
            assert_eq!(calls.get(), 0);
        }
        let other_home = NativeActionInputCustody::open(&path, "home:two", 32).unwrap();
        assert!(other_home.resolve(&reference).is_err());
        assert!(custody
            .prepare("admitted_input", "private", &"x".repeat(33))
            .is_err());
        let reduced = NativeActionInputCustody::open(&path, "home:one", 3).unwrap();
        assert!(reduced.resolve(&reference).is_err());
    }

    #[test]
    fn product_admission_survives_callback_loss_with_retained_reference_only() {
        let directory = tempfile::tempdir().unwrap();
        let input_path = directory.path().join("inputs.sqlite");
        let product_path = directory.path().join("product.sqlite");
        let custody = NativeActionInputCustody::open(&input_path, "home:issuer", 128).unwrap();
        let body = "private draft that must never enter the product command log";
        let reference = custody.prepare("admitted_input", "private", body).unwrap();
        let mut command = crate::host_action_admission_tests::command(false);
        command.inputs.insert("content".into(), reference.clone());
        let scope = command.instance_ref().unwrap();
        let dispatch = CommandDispatch {
            runtime_ref: "home:issuer:native".into(),
            command_ref: command.fingerprint().unwrap(),
        };
        let mut product = Store::open(product_path.to_str().unwrap()).unwrap();
        let contender = rusqlite::Connection::open(&input_path).unwrap();
        contender.busy_timeout(std::time::Duration::ZERO).unwrap();
        let lost = custody.publish(std::slice::from_ref(&reference), || {
            assert!(
                contender.execute_batch("BEGIN IMMEDIATE").is_err(),
                "publication must exclude competing collection and erasure"
            );
            product
                .admit_with_dispatch::<ProductActionAdmission>(
                    &scope,
                    &command.request_id,
                    command.clone(),
                    &dispatch,
                )
                .map_err(|_| invalid("product action admission refused"))?;
            Err::<(), _>(invalid("lost callback response after product commit"))
        });
        assert!(lost.is_err());
        contender
            .execute_batch("BEGIN IMMEDIATE; ROLLBACK")
            .unwrap();
        drop(contender);
        drop(product);
        drop(custody);
        let custody = NativeActionInputCustody::open(&input_path, "home:issuer", 128).unwrap();
        let mut product = Store::open(product_path.to_str().unwrap()).unwrap();
        assert_eq!(custody.resolve(&reference).unwrap().content, body);
        let replay = custody
            .publish(std::slice::from_ref(&reference), || {
                product
                    .admit_with_dispatch::<ProductActionAdmission>(
                        &scope,
                        &command.request_id,
                        command.clone(),
                        &dispatch,
                    )
                    .map_err(|_| invalid("product action admission refused"))
            })
            .unwrap();
        assert!(replay.replayed);
        let history = product
            .records(&scope, ProductActionAdmission::KIND)
            .unwrap();
        assert_eq!(history.len(), 1);
        assert!(!history[0].contains(body));
        let delivered = product
            .committed_dispatch::<ProductActionAdmission>(&scope, &command.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(delivered.command.inputs["content"], reference);
        assert!(!serde_json::to_string(&delivered.command)
            .unwrap()
            .contains(body));
        ContentStore::open(&input_path)
            .unwrap()
            .erase(&reference.version_ref, "t1")
            .unwrap();
        assert!(custody.resolve(&reference).is_err());
        let calls = Cell::new(0);
        assert!(custody
            .publish(&[reference], || {
                calls.set(1);
                Ok(())
            })
            .is_err());
        assert_eq!(calls.get(), 0);
        assert_eq!(
            product
                .records(&scope, ProductActionAdmission::KIND)
                .unwrap(),
            history
        );
    }

    #[test]
    fn invalid_preparation_or_retained_encoding_never_publishes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("inputs.sqlite");
        assert!(NativeActionInputCustody::open(&path, " ", 128).is_err());
        assert!(!path.exists());
        let custody = NativeActionInputCustody::open(&path, "home:one", 128).unwrap();
        assert!(custody.prepare("", "private", "content").is_err());
        assert!(custody.prepare("admitted_input", " ", "content").is_err());
        let raw = ContentStore::open(&path).unwrap();
        let future = serde_json::to_string(&RetainedInput {
            protocol: "gaugedesk.action-input.v2".into(),
            authority_scope: "home:one".into(),
            handle: "admitted_input".into(),
            label_ref: "private".into(),
            content: "content".into(),
        })
        .unwrap();
        for encoded in [
            b"not-json".as_slice(),
            br#"{"protocol":"future"}"#,
            future.as_bytes(),
            b"\xff\0",
        ] {
            let reference = ActionInput {
                handle: "admitted_input".into(),
                version_ref: raw.put(encoded).unwrap(),
                label_ref: "private".into(),
            };
            assert!(custody.resolve(&reference).is_err());
            assert!(custody
                .publish::<()>(&[reference], || panic!("invalid reference published"))
                .is_err());
        }
        assert!(custody
            .publish::<()>(&[], || panic!("empty publication"))
            .is_err());
    }
}
