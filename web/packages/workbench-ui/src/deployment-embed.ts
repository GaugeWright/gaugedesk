/**
 * The embed code for a deployment, as a website owner pastes it.
 *
 * The Home returns this exact text when it first publishes a deployment
 * (`customer_embed_html` in `crates/app/src/agent_release.rs`). Reopening the
 * deployment showed a shorter form with no loader and no panel elements, and
 * `<gw-session>` renders only the panel elements inside it, so that form
 * rendered nothing on the page it was pasted into. Both say the same thing now.
 */

export const PUBLIC_EMBED_LOADER_URL = "https://embed.gaugewright.com/embed.js";

/** Panels in the order the Home writes them. */
const PANEL_ORDER = ["chat", "viewer", "files", "chats"] as const;

export function deploymentEmbedHtml(address: string, components: Iterable<string>): string {
    const granted = new Set(components);
    const panels = PANEL_ORDER.filter((panel) => granted.has(`gw-${panel}`));
    const children = panels.map((panel) => `  <gw-${panel}></gw-${panel}>`).join("\n");
    return `<script type="module" src="${PUBLIC_EMBED_LOADER_URL}"></script>\n`
        + `<gw-session host="${address}" panels="${panels.join(",")}">\n${children}\n</gw-session>`;
}
