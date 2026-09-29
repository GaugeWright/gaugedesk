# Changelog

Every GaugeDesk release, newest first. A release is numbered `X.Y.Z`, and one
number covers everything it ships — every crate, package and bundle, the
desktop apps and the mobile apps alike (GaugeWright DR-0170). Before 1.0 the
middle number rises for a release that breaks something a user relies on:
data GaugeDesk has stored, the protocol between the app and a Home or the Hub,
the command line, configuration, or a published interface. The last number
rises for everything else.

Each release has one entry here, headed `## [X.Y.Z] — YYYY-MM-DD`, saying what
changed. An entry for a release that raises the middle number also says what
broke and what you must do about it. Changes gather under `## [Unreleased]` as
they land, and the release that ships them gives them its number and date. A
release cannot be cut without its entry.

Releases up to and including 0.4.30 are recorded on the
[release pages](https://github.com/GaugeWright/gaugedesk/releases), not here.

## [Unreleased]

- Raw context keeps authorized provider input items visible when another input
  is hidden, marking the hidden item's role in place. Unknown wire shapes hide
  the whole call, and unmapped request fields are omitted from partial views.
- Account-backed Raw context and Files reads now check a reader-specific grant
  against each new context import's exact file binding. Source owners can
  approve requests in the Context sources panel; old and ambiguous imports
  stay redacted.
- Raw context can show native Agent skills whose registered bytes still match
  the frozen discipline under the reader's current method grant.
- Raw context can show a delivered question answer while its exact answered
  record remains available to the current chat reader; changed answers redact.
- Account-backed chats require an explicit, revocable grant for each reader and
  installed Agent method version before Files or Raw context shows its source.
- The empty Chat pane keeps its composer at the bottom, with a browser layout check for the quick-start state.
- On macOS, Control-clicking a row in the navigator opens its menu and leaves
  it open. Before, the same press also acted on the row — a chat opened and
  took the cursor to its composer — and closed the menu.
- The desktop and mobile apps build GaugeDesk's own crates against the same
  dependency versions the rest of GaugeDesk is tested with; 69 of their pins
  had drifted.
- The iOS and Android apps carry the desktop's version number instead of one
  of their own (they said 0.4.3).
