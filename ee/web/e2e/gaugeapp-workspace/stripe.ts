// Isolated browser test adapter. No Stripe account, SDK request or payment.
export function loadConnectAndInitialize(options: { fetchClientSecret: () => Promise<string> }) {
    const record = (detail: string) => window.dispatchEvent(new CustomEvent("fixture-stripe", { detail }));
    record("initialized");
    void options.fetchClientSecret().then(() => record("session received"));
    return {
        create: () => {
            const element = document.createElement("div");
            element.textContent = "Embedded payment tool";
            return element;
        },
        logout: async () => { record("logged out"); },
    };
}
