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

## Intentional customization

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

Geometry tokens are `--gw-panel-width`, `--gw-panel-height`,
`--gw-panel-min-height`, `--gw-panel-padding`, `--gw-panel-border`,
`--gw-panel-radius`, and `--gw-panel-shadow`. Theme tokens are `--gw-bg`,
`--gw-panel`, `--gw-edge`, `--gw-ink`, `--gw-muted`, `--gw-brand-navy`, `--gw-accent`,
`--gw-accent-strong`, `--gw-accent-hover`, `--gw-accent-contrast`, `--gw-warn`,
`--gw-bad`, `--gw-font`, `--gw-serif`, `--gw-mono`, `--gw-font-size-label`,
`--gw-font-size-small`, `--gw-font-size-ui`, `--gw-font-size-body`,
`--gw-font-size-title`, and `--gw-color-scheme`.

Every panel exposes `::part(panel)` plus a panel-specific alias such as
`::part(panel-chat)` or `::part(panel-files)`. The single branding owner also
exposes `::part(attribution)`. Use these parts for deliberate exceptions; use a
wrapper or `<gw-session>` itself for multi-panel grid and page-level spacing.
