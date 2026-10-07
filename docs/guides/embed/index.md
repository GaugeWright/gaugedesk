# Publish an agent on a website

Website agents have a production proof, but general self-service access is not
available. Contact GaugeWright before promising this feature.

You need a published version, a way to pay for visitors' use (GaugeWright
billing on an account you administer, or a provider key you store), exact
allowed website origins, session/spend/retention limits, and a visitor privacy
notice.

## Configure and test

1. Select the fixed version and confirm its tools, model, panel types,
   initial files, and output limits.
2. Configure origins, visitor identity, session and concurrency limits, spend,
   retention, and who pays. Who pays decides the model provider: GaugeWright
   billing runs on managed inference, and a stored key runs on that key's
   provider.
3. If the deployment collects a result, define its eligible content, schema,
   recipient, size limit, and whether collection is required.
4. Try the agent in a preview chat before deploying. A preview runs on your
   own usual model and funding, so it does not exercise the website panels,
   origins, or visitor sign-in. Check an allowed and a blocked origin,
   refresh/resume, limits, provider failure, and collection validation on the
   deployment itself.

A pinned model that the chosen funding cannot serve is refused at publish;
there is no shared-key fallback. Collection rules cannot change during a run.

## Publish and update

Publishing creates a signed, immutable release. Copy the generated integration
code to an allowed site. New sessions use the active release; sessions already
running remain pinned to their original release.

The hosted runtime serves visitors even when the author's computer is offline.
Monitor use, spend, errors, and collected results. Publish a new fixed version
to update the deployment. Downloaded visitor material enters quarantine for
review.

## Style the panels

Each panel element (`<gw-chat>`, `<gw-viewer>`, `<gw-files>`, `<gw-chats>`)
draws inside its own shadow root, so ordinary page CSS does not reach into it.
Theme it with the public `--gw-*` custom properties instead. Set them on
`<gw-session>`, or on any ancestor; they inherit into every panel. Panels are
dark unless you set them.

| Token | What it sets |
| --- | --- |
| `--gw-bg` | Panel background |
| `--gw-panel` | Raised surfaces inside a panel |
| `--gw-edge` | Borders and rules |
| `--gw-ink` | Text |
| `--gw-muted` | Secondary text |
| `--gw-navy` | GaugeWright brand detail |
| `--gw-accent`, `--gw-accent-strong`, `--gw-accent-hover` | Links, focus, and actions |
| `--gw-on-accent` | Text on an accent fill |
| `--gw-warn`, `--gw-danger` | Warnings and errors |
| `--gw-color-scheme` | `light` or `dark`, for native controls and scrollbars |
| `--gw-font-chrome`, `--gw-font-prose`, `--gw-font-mono` | Interface, message, and code faces |
| `--gw-font-size-label`, `-small`, `-ui`, `-body`, `-title` | Type sizes |

Size and frame each panel with these, not with `width`, `height`, `margin`,
`padding` or `border` on the element itself, which the panel overrides:

| Token | Default |
| --- | --- |
| `--gw-panel-width` | `100%` |
| `--gw-panel-height`, `--gw-panel-min-height` | Set per panel type |
| `--gw-panel-padding` | `12px` |
| `--gw-panel-border` | `1px solid` the edge color; a full `border` value, not a color |
| `--gw-panel-radius` | `12px` |
| `--gw-panel-shadow` | A soft drop shadow; a full `box-shadow` value |

A light theme:

```css
gw-session {
  --gw-color-scheme: light;
  --gw-bg: #ffffff;
  --gw-panel: #f6f7f9;
  --gw-edge: #d9dde3;
  --gw-ink: #1d232b;
  --gw-muted: #5f6b7a;
  --gw-accent: #2f6fdb;
  --gw-accent-strong: #1f57b8;
  --gw-accent-hover: #255fc4;
  --gw-on-accent: #ffffff;
  --gw-warn: #b26a00;
  --gw-danger: #c62828;
  --gw-panel-shadow: 0 4px 16px rgb(0 0 0 / 8%);
}
```

Panels do not follow the visitor's light or dark setting on their own. To
follow it, put your overrides inside `@media (prefers-color-scheme: light)`.

For anything the tokens do not cover, each panel's outer box is exposed as a
CSS part: `gw-chat::part(panel)`, or `::part(panel-chat)`, `panel-viewer`,
`panel-files` and `panel-chats` to target one type. The "Powered by
GaugeWright" mark is `::part(attribution)`.

## Visitor notice

Before accepting visitor data, disclose the operator, purpose, model provider,
GaugeWright hosting, collection, retention, privacy contact, and support path.
Do not claim local inference, SOC 2, ISO 27001 certification, or an independent
penetration test.

See [Current limits](../../reference/limitations.md).
