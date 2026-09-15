import { loadConnectAndInitialize, type ConnectElementTagName } from "@stripe/connect-js";
import { createSignal, onCleanup, onMount, type JSX } from "solid-js";

export interface StripeAccountSession {
    readonly client_secret: string;
    readonly publishable_key: string;
    readonly component: ConnectElementTagName;
}

/**
 * Stripe owns the financial-account form and its sensitive values. GaugeDesk
 * obtains a short-lived component session for exactly one admitted component
 * and never renders bank, identity, tax, payout, or dispute fields itself.
 */
export function StripeEmbeddedComponent(props: {
    readonly component: ConnectElementTagName;
    readonly createAccountSession: () => Promise<StripeAccountSession>;
}): JSX.Element {
    let host!: HTMLDivElement;
    const [failure, setFailure] = createSignal("");
    let disposed = false;
    let initialSecret: string | null = null;
    let connect: ReturnType<typeof loadConnectAndInitialize> | undefined;
    const assertMounted = () => {
        if (disposed) throw new DOMException("This payment tool is no longer open.", "AbortError");
    };
    onCleanup(() => {
        disposed = true;
        initialSecret = null;
        host?.replaceChildren();
        // Logout ends this embedded session; it does not disconnect the
        // organization's processor account or undo an admitted payment.
        if (connect) void connect.logout().catch(() => undefined);
    });

    onMount(() => {
        void (async () => {
            try {
                const initial = await props.createAccountSession();
                assertMounted();
                initialSecret = initial.client_secret;
                const fetchClientSecret = async () => {
                    assertMounted();
                    if (initialSecret) {
                        const secret = initialSecret;
                        initialSecret = null;
                        return secret;
                    }
                    const result = await props.createAccountSession();
                    assertMounted();
                    return result.client_secret;
                };
                connect = loadConnectAndInitialize({
                    publishableKey: initial.publishable_key,
                    fetchClientSecret,
                    appearance: { overlays: "dialog" },
                });
                host.replaceChildren(connect.create(props.component));
            } catch (error) {
                if (!disposed) setFailure(error instanceof Error ? error.message : String(error));
            }
        })();
    });

    return <div class="gaugeapp-stripe-component" data-stripe-component={props.component}>
        <ShowFailure failure={failure()} />
        <div ref={host} />
    </div>;
}

function ShowFailure(props: { readonly failure: string }): JSX.Element {
    return props.failure ? <p class="gaugeapp-unavailable" role="alert">{props.failure}</p> : <></>;
}
