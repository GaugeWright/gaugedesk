/**
 * Prototype bench for the sign-in card, in the manner of settings-lab and
 * whip-lab: the real component against the real stylesheet, so what is agreed
 * here is what ships. The card below is {@link SignInCard} itself.
 *
 * It staged the argument for this card before it existed — two sign-in screens,
 * one per distro, drifting apart — and that argument is now in git rather than
 * on this page. What it stages today is the card's states, which a live control
 * plane will not produce on demand: an address that routes to an organization,
 * one that does not, and the account-creation step behind it.
 *
 * The one thing this cannot be honest about is the organization's *name*.
 * Production discovery does not learn it — `POST /auth/work-email` redirects or
 * answers a flat 404, and the redirect's destination is not readable — so the
 * shipped card reads "your organization". The bench passes a name anyway, to
 * exercise the branch that has one, against the day a discovery route returns it.
 *
 * Served in development only (`/signin-lab.html`); no shipped bundle names this
 * entry.
 */
import { createSignal, type JSX } from "solid-js";
import { render } from "solid-js/web";
import { SignInCard, type SignInRoute } from "@gaugewright/workbench-ui";
import "@gaugewright/workbench-ui/styles.css";

/** Stands in for `resolveSignInRoute`. Two domains are connected; every other
 *  address gets the one flat answer the real route gives, which is what keeps
 *  discovery from enumerating accounts. */
const CONNECTED_DOMAINS: Readonly<Record<string, string>> = {
    "acme.com": "Acme Corporation",
    "wanamaker.org": "Wanamaker Institute",
};
const benchResolve = async (email: string): Promise<SignInRoute> => {
    await new Promise((r) => setTimeout(r, 260));
    const label = CONNECTED_DOMAINS[email.split("@")[1]?.toLowerCase() ?? ""];
    return label ? { kind: "organization", label, go: () => undefined } : { kind: "personal" };
};

/** Nothing here reaches a network: the bench judges the surface, and a real
 *  round trip would only add latency to a decision about layout. */
const benchPasskey = {
    signIn: async () => undefined,
    beginCreation: async () => ({ challengeId: "bench", expiresIn: 600 }),
    // Shaped like the real batch — ten codes, three groups of four from the
    // unambiguous alphabet — so the panel is judged at the size it will be.
    finishCreation: async () => [
        "HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K", "TQ2H-XM8R-C4JP", "N7YF-DK5W-GH3Q",
        "R4MX-P9TB-JL2V", "W8CJ-Q3NR-YK7D", "F5HT-M2XP-B6WL", "K9QN-V4DJ-TR8M",
        "X3PL-H7BF-N5CQ", "D6RW-J8KM-P2TY",
    ],
    complete: () => undefined,
};
const benchRecovery = {
    start: async () => ({ challengeId: "bench", expiresIn: 600 }),
    finish: async () => undefined,
    complete: () => undefined,
};
const BENCH_CODES = [
    "HKPR-7T2M-QJ4X", "B9WD-LN3F-VZ6K", "TQ2H-XM8R-C4JP", "N7YF-DK5W-GH3Q",
    "R4MX-P9TB-JL2V", "W8CJ-Q3NR-YK7D", "F5HT-M2XP-B6WL", "K9QN-V4DJ-TR8M",
    "X3PL-H7BF-N5CQ", "D6RW-J8KM-P2TY",
];
/** The two provider-signup returns, which a live control plane produces only
 *  after a real round trip to a real provider (DR-0189 §4).
 *
 *  `attested` is Google's: the address is evidence and the card shows it. `code`
 *  is Microsoft's: Entra attests nothing, so the address is a prefill the person
 *  may correct and a code proves it. They are staged side by side because the
 *  extra step is the part of this worth looking at. */
const benchProviderSignup = {
    attested: {
        email: "person@example.test",
        suggestedName: "Person One",
        providerLabel: "Google",
        create: async () => BENCH_CODES,
        complete: () => undefined,
    },
    code: {
        email: "work.person@contoso.test",
        suggestedName: "Work Person",
        providerLabel: "Microsoft",
        emailProof: {
            start: async () => ({ challengeId: "bench", expiresIn: 600 }),
            finish: async () => BENCH_CODES,
        },
        create: async () => BENCH_CODES,
        complete: () => undefined,
    },
} as const;

function Lab(): JSX.Element {
    const [nonce, setNonce] = createSignal(0);
    const [signup, setSignup] = createSignal<"none" | "attested" | "code">("none");
    const restage = (next: "none" | "attested" | "code") => {
        setSignup(next);
        setNonce(nonce() + 1);
    };
    return (
        <div class="lab">
            <header class="lab-head">
                <h1>Sign-in card</h1>
                <p>
                    The shipped component against the shipped stylesheet. Nothing on
                    this page styles a product class — bench chrome only, or the
                    prototype would flatter itself and what is agreed here would not
                    survive the move into the app.
                </p>
                <div class="lab-actions">
                    <label class="lab-toggle">
                        <button class="lab-reset" type="button" onClick={() => setNonce(nonce() + 1)}>
                            Reset the card
                        </button>
                    </label>
                    <label class="lab-toggle">
                        <button class="lab-reset" type="button" onClick={() => restage("none")}>
                            Signed out
                        </button>
                    </label>
                    <label class="lab-toggle">
                        <button class="lab-reset" type="button" onClick={() => restage("attested")}>
                            Google return
                        </button>
                    </label>
                    <label class="lab-toggle">
                        <button class="lab-reset" type="button" onClick={() => restage("code")}>
                            Microsoft return
                        </button>
                    </label>
                    <span class="lab-note">
                        Try an address at <code>acme.com</code> or <code>wanamaker.org</code> for
                        the organization branch; anything else takes the personal one. The two
                        provider returns stage what a first-time signup sees — Google attests the
                        address, Microsoft does not, so that one asks for a code (DR-0189).
                    </span>
                </div>
            </header>

            <div class="lab-stage lab-stage--tall">
                {/* Keyed on the nonce so "reset" rebuilds the card from its first
                    step rather than reaching into its internals. */}
                {(() => {
                    nonce();
                    return (
                        <div class="homegate-scrim">
                            <section class="homegate-card">
                                <SignInCard
                                    title="Sign in"
                                    lede="Sign in to save model credentials, settings, and link your chats."
                                    resolve={benchResolve}
                                    passkey={benchPasskey}
                                    recovery={benchRecovery}
                                    providerSignup={
                                        signup() === "none" ? undefined : benchProviderSignup[signup() as "attested" | "code"]
                                    }
                                    providers={[
                                        { id: "google", label: "Continue with Google", begin: () => restage("attested") },
                                        { id: "microsoft", label: "Continue with Microsoft", begin: () => restage("code") },
                                        { id: "apple", label: "Continue with Apple (not yet available)", begin: () => undefined },
                                    ]}
                                    footnote={
                                        <span class="signin__quiet">
                                            No sign up necessary.{" "}
                                            <button class="signin__link" type="button" onClick={() => undefined}>
                                                Configure a model credential
                                            </button>
                                        </span>
                                    }
                                />
                            </section>
                        </div>
                    );
                })()}
            </div>
        </div>
    );
}

render(() => <Lab />, document.getElementById("root")!);
