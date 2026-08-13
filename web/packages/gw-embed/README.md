# GaugeDesk embeddable panels

The `embed.js` module registers `<gw-session>` and the `<gw-chat>`,
`<gw-viewer>`, `<gw-files>`, and `<gw-chats>` panels. Each panel ships with its
own isolated typography, colour, frame, spacing, and minimum size; a host page
only needs to choose how multiple panels are arranged.

```html
<script type="module" src="https://embed.gaugewright.com/embed.js"></script>
<gw-session host="https://panels.gaugewright.com/d/example" panels="chat">
  <gw-chat></gw-chat>
</gw-session>
```

`<gw-chat>` includes a **New session** action. It replaces the panel's current
conversation with a fresh deployment session; authenticated visitors can still
reopen their owned earlier conversations through **Chats**.

Anonymous session creation is protected by Cloudflare Turnstile. The managed
check appears only when a new engagement is required: a valid resume continues
without interruption, while **New session** requests a fresh check. No extra
markup or JavaScript is required.

If your site has a Content Security Policy, admit Turnstile alongside the
GaugeDesk embed:

```text
script-src https://embed.gaugewright.com https://challenges.cloudflare.com;
connect-src https://panels.gaugewright.com wss://panels.gaugewright.com https://challenges.cloudflare.com;
frame-src https://challenges.cloudflare.com;
```

Keep any existing sources in those directives. Turnstile's challenge uses the
same public `--gw-*` color, type, border, and radius settings as the panels and
is isolated from accidental page-wide CSS overrides.

Add an optional, pre-filled first assistant line directly in the markup:

```html
<gw-chat
  agent-name="Avery"
  opening-message="Hi, I’m your advisor. What would you like to explore?"
></gw-chat>
```

`agent-name` replaces the generic **Agent** transcript label and gives the
composer a matching **Ask Avery…** prompt. Leave it out to keep the generic
label. The attribute is ordinary, visible HTML and can be changed without CSS
or JavaScript.

The opening message costs no model turn. It remains visible as the first line of
the conversation and appears again when the visitor starts a new session. It is
host-authored presentation content, not a retained model response.

## Customize the CSS

Customization is optional. The default panel styles are complete and isolated
inside the components.

For an editable starting point, open the unminified
[`embed.css`](https://embed.gaugewright.com/embed.css), save it with your site's
CSS, and load your copy after the rest of your site styles:

```html
<link rel="stylesheet" href="/css/gaugedesk-embed.css">
```

The file contains every public setting, its default value, and comments saying
what it changes. Edit the values directly; no build tool or JavaScript is
needed. Because your site owns the copied file, upgrades to `embed.js` will not
overwrite your choices.

For a small change, skip the file and put only the setting you need in your
existing stylesheet:

Set public `--gw-*` properties on `<gw-session>` to theme every child panel, or
on one panel to change it alone. Structural host rules are protected inside the
shadow boundary so broad page selectors cannot accidentally collapse or pad a
panel.

```css
gw-session {
  --gw-bg: #101827;
  --gw-panel: #172238;
  --gw-edge: #31415f;
  --gw-ink: #eef3fa;
  --gw-muted: #9aa8bc;
  --gw-accent: #72a7ff;
  --gw-panel-radius: 16px;
  --gw-panel-padding: 14px;
  --gw-panel-shadow: 0 18px 48px rgb(0 0 0 / 28%);
}

gw-chat {
  --gw-panel-min-height: 560px;
}

gw-chat::part(panel) {
  box-shadow: none;
}
```

The public settings are grouped plainly in `embed.css`: colors, actions and
status, panel frame, typography, and the default height of each panel. That file
is generated from the panels' own defaults, so it always states what a panel
does when you change nothing — re-download it rather than assuming an older copy
still describes the current defaults. Your saved copy is yours; nothing
regenerates it.

### Renamed settings

Seven settings were renamed to match the GaugeWright palette. **The former names
still work**, so a copy of `embed.css` saved before the rename keeps doing
exactly what it did, and there is nothing you need to change.

| Former name | Current name |
|---|---|
| `--gw-brand-navy` | `--gw-navy` |
| `--gw-accent-contrast` | `--gw-on-accent` |
| `--gw-bad` | `--gw-danger` |
| `--gw-font`, `--gw-serif` | `--gw-font-chrome` |
| `--gw-prose` | `--gw-font-prose` |
| `--gw-mono` | `--gw-font-mono` |

Where both are set, the current name wins.

Every panel exposes `::part(panel)` plus a panel-specific alias such as
`::part(panel-chat)` or `::part(panel-files)`. The single branding owner also
exposes `::part(attribution)`. Use parts for deliberate one-off CSS rules. Use a
wrapper or `<gw-session>` itself only for multi-panel layout and page-level
spacing.
