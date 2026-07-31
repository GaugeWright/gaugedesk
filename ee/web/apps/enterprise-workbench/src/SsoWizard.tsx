/**
 * Guided SSO setup wizard (M3 `ONB-4`, [ADR 0058](../../../../specs/decisions/0058-self-serve-enterprise-onboarding.md)).
 *
 * The default first-run path for an IT admin: **Connect** (paste our SP values into the
 * IdP, enter the IdP's back) → **Test** (a real discovery round-trip, `ONB-3`) →
 * **Provision** (issue a SCIM token; note that JIT auto-provisions verified-domain
 * users, `ONB-2`) → **Enforce**. A thin orchestration over the existing control-plane
 * methods — the flat `AdminEnvironment` sections remain for power users.
 */

import { createResource, createSignal, For, type JSX, Show } from "solid-js";
import type { EnterpriseAdminApi, SsoConnection } from "@gaugewright/enterprise-client";

const STEPS = ["Connect", "Test", "Provision", "Enforce"] as const;

export function SsoWizard(props: { api: EnterpriseAdminApi; onProposeSso: (connection: SsoConnection) => Promise<unknown>; onProposeScim: () => Promise<unknown>; onClose: () => void }): JSX.Element {
    const [step, setStep] = createSignal(0);
    const [integration] = createResource(() => props.api.adminIntegration());

    const [protocol, setProtocol] = createSignal("oidc");
    const [issuer, setIssuer] = createSignal("");
    const [audiences, setAudiences] = createSignal("");
    const [rolesClaim, setRolesClaim] = createSignal("");
    const [status, setStatus] = createSignal("");
    const [testMsg, setTestMsg] = createSignal("");

    const connection = (): SsoConnection => ({
        protocol: protocol(),
        issuer: issuer().trim(),
        audiences: audiences()
            .split(",")
            .map((a) => a.trim())
            .filter(Boolean),
        metadata: "",
        enforce_sso: false,
        claim_mapping: rolesClaim().trim() ? { roles_claim: rolesClaim().trim() } : undefined,
    });

    const run = async (verb: string, fn: () => Promise<unknown>) => {
        setStatus(`${verb}…`);
        try {
            await fn();
            setStatus(`${verb} ✓`);
        } catch (e) {
            setStatus(`could not ${verb}: ${e instanceof Error ? e.message : String(e)}`);
        }
    };

    return (
        <div class="modal-overlay" onClick={() => props.onClose()}>
            <div
                class="modal sso-wizard"
                data-sso-wizard
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => e.key === "Escape" && props.onClose()}
            >
                <div class="modal-head">
                    <h3>Set up SSO</h3>
                    <button type="button" onClick={() => props.onClose()}>
                        close
                    </button>
                </div>

                <ol class="wizard-steps" data-wizard-steps>
                    <For each={STEPS}>
                        {(label, i) => (
                            <li classList={{ active: i() === step(), done: i() < step() }}>
                                {i() + 1}. {label}
                            </li>
                        )}
                    </For>
                </ol>

                {/* Step 1 — Connect */}
                <Show when={step() === 0}>
                    <section class="wizard-pane" data-wizard-connect>
                        <p class="muted">Paste these into your IdP:</p>
                        <Show when={integration()}>
                            {(d) => (
                                <ul class="integration-list">
                                    <li class="integration-row">
                                        <span class="integration-label">OIDC redirect URI</span>
                                        <code class="integration-value">{d().oidc.redirect_uri}</code>
                                    </li>
                                    <li class="integration-row">
                                        <span class="integration-label">SAML metadata URL</span>
                                        <code class="integration-value">{d().saml.metadata_url}</code>
                                    </li>
                                    <li class="integration-row">
                                        <span class="integration-label">SCIM base URL</span>
                                        <code class="integration-value">{d().scim.base_url}</code>
                                    </li>
                                </ul>
                            )}
                        </Show>
                        <p class="muted">…then enter your IdP's values:</p>
                        <label>
                            Protocol
                            <select value={protocol()} onChange={(e) => setProtocol(e.currentTarget.value)}>
                                <option value="oidc">OIDC</option>
                                <option value="saml">SAML</option>
                            </select>
                        </label>
                        <label>
                            Issuer
                            <input
                                data-wizard-issuer
                                value={issuer()}
                                onInput={(e) => setIssuer(e.currentTarget.value)}
                                placeholder="https://idp.example.com"
                            />
                        </label>
                        <label>
                            Audiences (client id, comma-separated)
                            <input
                                value={audiences()}
                                onInput={(e) => setAudiences(e.currentTarget.value)}
                                placeholder="client-id"
                            />
                        </label>
                        <label>
                            Roles claim (optional)
                            <input
                                value={rolesClaim()}
                                onInput={(e) => setRolesClaim(e.currentTarget.value)}
                                placeholder="roles / groups"
                            />
                        </label>
                        <button
                            type="button"
                            class="tree-action"
                            onClick={() => run("propose connection", () => props.onProposeSso(connection()))}
                        >
                            Save connection
                        </button>
                    </section>
                </Show>

                {/* Step 2 — Test */}
                <Show when={step() === 1}>
                    <section class="wizard-pane" data-wizard-test>
                        <p class="muted">Check the IdP is reachable and its keys load before going live.</p>
                        <button
                            type="button"
                            class="tree-action"
                            data-wizard-test-btn
                            onClick={async () => {
                                setTestMsg("testing…");
                                try {
                                    const r = await props.api.adminTestSso(connection());
                                    setTestMsg((r.ok ? "✓ " : "✗ ") + r.detail);
                                } catch (e) {
                                    setTestMsg(`test failed: ${e instanceof Error ? e.message : String(e)}`);
                                }
                            }}
                        >
                            Test connection
                        </button>
                        <Show when={testMsg()}>
                            <p class="status" data-wizard-test-result>
                                {testMsg()}
                            </p>
                        </Show>
                    </section>
                </Show>

                {/* Step 3 — Provision */}
                <Show when={step() === 2}>
                    <section class="wizard-pane" data-wizard-provision>
                        <p class="muted">
                            New sign-ins from a verified domain auto-provision as members (JIT). For full
                            lifecycle (deprovisioning, groups → roles), connect SCIM:
                        </p>
                        <button
                            type="button"
                            class="tree-action"
                            onClick={() =>
                                run("issue SCIM token", async () => {
                                    await props.onProposeScim();
                                })
                            }
                        >
                            Issue SCIM token
                        </button>
                        <p class="muted">Review the proposal in identity.json. The one-time token appears only after approval.</p>
                    </section>
                </Show>

                {/* Step 4 — Enforce */}
                <Show when={step() === 3}>
                    <section class="wizard-pane" data-wizard-enforce>
                        <p class="muted">
                            Require all members to sign in via the IdP. The last break-glass owner can
                            always still get in.
                        </p>
                        <button
                            type="button"
                            class="tree-action"
                            onClick={() =>
                                run("enforce SSO", () =>
                                    props.onProposeSso({ ...connection(), enforce_sso: true }),
                                )
                            }
                        >
                            Enforce SSO
                        </button>
                    </section>
                </Show>

                <p class="status" data-wizard-status>
                    {status()}
                </p>

                <div class="wizard-nav">
                    <button
                        type="button"
                        class="tree-action"
                        disabled={step() === 0}
                        onClick={() => setStep((s) => Math.max(0, s - 1))}
                    >
                        Back
                    </button>
                    <Show
                        when={step() < STEPS.length - 1}
                        fallback={
                            <button type="button" class="tree-action" data-wizard-done onClick={() => props.onClose()}>
                                Done
                            </button>
                        }
                    >
                        <button
                            type="button"
                            class="tree-action"
                            data-wizard-next
                            onClick={() => setStep((s) => Math.min(STEPS.length - 1, s + 1))}
                        >
                            Next
                        </button>
                    </Show>
                </div>
            </div>
        </div>
    );
}
