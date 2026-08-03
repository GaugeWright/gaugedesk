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
status, panel frame, typography, and the default height of each panel.

Every panel exposes `::part(panel)` plus a panel-specific alias such as
`::part(panel-chat)` or `::part(panel-files)`. The single branding owner also
exposes `::part(attribution)`. Use parts for deliberate one-off CSS rules. Use a
wrapper or `<gw-session>` itself only for multi-panel layout and page-level
spacing.
