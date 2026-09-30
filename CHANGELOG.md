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

## [0.5.0] — 2026-09-30

- First sign-in on a fresh computer opens its local Home directly when the
  account has no Home or shared projects. A Home’s owner can let their other
  signed-in accounts use the same computer and its projects.

- Chats can notify your device when a turn ends, with notification and sound
  preferences in Settings.

- Desktop organization SSO now completes the same account sign-in handoff as
  other sign-in methods. Organization management requires the selected live
  account and closes when that account loses admission. The organization picker
  appears only for an account that can create an organization or belongs to one.

- The desktop app no longer shows "Checking for updates…" indefinitely when
  this computer's Home does not admit the signed-in account. It checks at once;
  an update found before the account's release policy can be read is shown as
  waiting for your account and installs once the policy allows it. A check
  that gets no answer in 30 seconds reports that it could not complete.

- Queued native file actions now recheck account-session idle bounds and the
  bound device before execution. Provider refresh cannot extend a retained
  dispatch grant beyond the deadline originally admitted for it.

- Management Agents tolerate model providers that take more than two seconds
  to begin responding, and remain stoppable during the wait.

- Opaque account sessions enforce their idle timeout on requests as well as
  refreshes. The Hub identity response now reports non-secret session bounds
  for native Home authentication, without exposing provider credentials or work.

- iOS builds require iOS 15 or later. Devices still running iOS 14 must update
  their operating system to install or update GaugeDesk.

- Selecting a Home after desktop sign-in updates the signed-in account at the
  Hub. Registered relay-only Homes are selected by identity rather than dialed
  as empty endpoints, and selection failures are shown on the recovery card.

- Account sign-in requires its session record to be saved successfully. Cached
  credentials cannot bypass a revoked or missing session record, changed
  session bounds, or a revoked device when authorizing work.

## [0.4.31] — 2026-09-30

- Workshop Agents and top-level project groups start collapsed; expand a group
  with its caret to see its children.

- Native Agent improvement now reads streamed answers from OpenAI-compatible
  model connections and runs both comparison arms before opening held-out cases.

- The desktop Agent Workshop can evaluate an edited Agent against its sampled
  case pool, show a regularized reviewer result, send open-case feedback back
  to the edit chat, and apply a selected candidate to an unchanged draft.
  Held-out cases and checks stay in Home custody; publishing remains separate.

- A chat's changes name each target folder instead of showing its internal
  id, and a folder renamed in the chat shows as a rename. When two chats
  rename one folder differently, the conflicted chat offers keeping its name
  or using the shared one, and a conflicted change stays visible instead of
  reading as discarded. A target can now be renamed from the project's
  settings. On hosted placements an agent's folder rename is kept once the
  Home confirms it after the turn (DR-0248).

- The agent in a work chat now sees each of the chat's targets as a folder
  named after the target, such as `api/src/main.rs`, instead of an encoded
  `targets/t-…` path, and never sees a target's permanent id. Renaming that
  folder, by the agent's `mv` or from the Files pane, renames the target on the
  chat's line; the rest of the project takes the new name when the line reaches
  Main. Target names must now work as folder names and be unique in their
  project; existing names that are not are adjusted once, at startup
  (DR-0248).

- Hosted GaugeDesk now offers Privacy & analytics controls: people can opt out
  per account, and organization owners can disable feature usage collection
  for their organization. The first measured actions are chat creation and
  chat turns, with no work content in events.
- New Agents seed an editable `SYSTEM.md` for their system-level method text;
  `AGENTS.md` carries standing developer guidance. Provider requests preserve
  those roles, while effective tools and environment come from the runtime.
- Raw context keeps authorized provider input items visible when another input
  is hidden, marking the hidden item's role in place. Unknown wire shapes hide
  the whole call even when every logical source is readable, and unmapped
  request fields are omitted from partial views.
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
