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

## [0.8.1] — 2026-10-07

- The mobile app now finds a Machine that is reachable only through the relay.
  It reads the routes your desktop publishes to its signed account directory,
  as GaugeDesk in a browser already did, instead of only the Hub's route list,
  which never carried them. A route that reaches the phone only through the Hub
  keeps its address but no longer brings a relay pin.
- A Panel agent whose visitors may read or create files, or answer questions,
  now replies to visitors. Every such visitor message was refused before the
  model ran ("ungoverned handle `workspace.read`"), because the published
  release did not cover the built-in download and question tools. Publish a new
  version of an affected Panel agent and update its deployments to pick this up.
- Previewing a Panel agent now behaves as a deployment does when its
  instructions write to `outbox/`, `artifacts/` or `work/`.
- The settings assistants in Agent, Panel and Project Settings, Account
  Settings, Administration and Commercial Operations understand the names on
  their pages, and one message can make several changes. Asked to change a
  Panel agent, the assistant says the change reaches visitors once a new
  version is published and its deployments are updated.
- Returning to Browse shows the chat you are in, including an Agent's edit
  chats and previews in Workshop, instead of collapsed Projects.
- A collection's result format is documented as a label: it names the
  collected file's format and is not checked against its contents.
- Typing a first message into the empty chat pane runs it again. Since 0.8.0
  the new chat opened but its first turn could be refused with "couldn't run
  that turn — Task project selection changed", because the turn started before
  the chat's project was selected.

## [0.8.0] — 2026-10-06

- A project created in GaugeDesk can now be handed off to a paired computer.
  The receiving computer used to refuse every such project because both held
  their own copy of the built-in Default Agent; it now uses its own. A project
  handed off from a signed-out window arrives as the receiving computer's
  signed-out work, where its window can see it, and a project's settings open
  its paired-device handoff, invite and co-drive pane again (People & sharing
  ▸ Paired devices…).

- Project Model access shows a loading or unavailable message when organization
  model access has not loaded, instead of crashing the settings page.

- When the account service cannot be reached, the Panel deployment dialog
  explains the temporary connectivity problem and lets you retry the account
  list without closing the dialog.

- Every account signed in on a desktop now has keys of its own there, and
  signing in makes that computer reachable for the account under them: the
  computer publishes its own directory entry, and signing out withdraws it
  while the account's other computers stay reachable. An account's first
  computer creates its keys; approving another computer from it hands them
  over. The account that claimed a computer moves off the computer's own key,
  which signs the hand-over so browsers that trusted it follow. Publishing an
  account's root to the Hub now carries proof from one of the account's own
  devices.
- The storage layer can initialize and reopen a dedicated product database for
  an exact project Home, with independently retained identity and missing-file
  refusal. Existing projects still use the explicit migration path; this does
  not activate new Home storage. The product schema moves to version 13, which
  older builds refuse.

- A provider key you allow for Home use now reaches every GaugeWright-hosted
  Home you work in — your own and your organizations' — without linking it
  there again. Each Home gets its own sealed copy, which one of your devices
  seals for it. It loses that copy when you leave the Home's organization,
  remove Home use from the key, or revoke the key. Provider sign-ins (Codex,
  Grok) stay on your devices for now. The Hub serves this to Homes at
  `GET /account/home-links/{home}`.

- An organization's owners and admins reach the organization's own shared
  projects again, including Model access, without needing a project grant. On
  hosted GaugeWright they had been refused them with "not in scope for this
  project". Other roles still need a grant, and no role reaches another
  organization's or another account's projects (DR-0374).

- Federated runs refuse an unreadable organization placement policy instead of
  treating it as an open policy. Absent and explicitly open policies are unchanged.

- Long-lived runs, target settlements, managed machine executions and GaugeVault
  credentials no longer re-read their whole history on every change: the store
  checkpoints their state every 64 events and continues from there. The store
  schema moves to version 12; an older build refuses a store this one has opened.

- A Home composed with a verified-funding producer now pays managed work chats
  from credits: each model call, compaction included, holds its input plus
  8,192 output tokens at the model's price plus 20% before it is sent, and the
  turn settles from its usage. A model with no known price is refused, and a
  call whose outcome is unknown keeps its hold rather than being sent again.

- Align the embed browser palette assertion with the current carried GaugeWright navy token.

- Office Home integrations can require encrypted library metadata before startup
  loads or seeds project and chat titles. Missing keys, incompatible history
  and unavailable encryption refuse startup. Clinical mode remains disabled.

- Revoking a trusted device now says which of your provider links it held, so
  you can replace those keys if you no longer trust it. Its copies of them are
  deleted either way.

- Signing in again on a desktop no longer adds another copy of that computer
  to your Trusted Devices: the new sign-in retires the device the previous one
  made, and your provider links stop being sealed for it.

- Project settings → People & sharing lists the invitations still waiting to
  be accepted. Each can be cancelled, which stops its link working, or sent
  again, which makes a fresh link and stops the earlier one.

- An email invitation can be emailed from Project settings: "Email it to …"
  beside a new link asks GaugeWright to send it, naming you by your verified
  address and never naming the project. An account may send twenty a day.

- Update the browser build dependency to reject malformed source maps that can stall processing.

- Apply configured content encryption to typed lifecycle events and refuse unreadable protected history during approval and receipt checks.

- Office result publication records its exact original events and output facts
  for later verification. The additive store update requires schema 11 support.

- Concurrent local Home startup preserves one content-encryption key, preventing
  another initializer from replacing it and making earlier data unreadable.

- Content storage supports an explicitly selected format that authenticates each
  protected record’s scope and kind. Strict reading refuses legacy records;
  clinical enrollment and migration remain required before enabling that mode.

- Office task results retain their original staff authorization when advancing a shared Home, including recovery after interrupted result publication.

- Native upload publication retains every file in its complete resource binding
  and refuses files outside the chat selected view, even when recorded in its
  cut. Buffered handler integration remains in progress.

- Buffered HTTP handlers can finish the exact command claimed by their
  middleware. A refused response preserves a receipt already committed by the
  handler; work without a receipt keeps its ordinary failure status.

- Office staff streamed uploads use the original session at guarded file and
  native history commits. Only the uploaded file enters its attributed cut;
  native bytes stay retained through the atomic resource and original receipt
  commit. A failed resource publication creates no partial access grant.
  Completion events and responses recheck the original staff session; denied
  delivery cannot turn an already committed upload into a rejected command.

- GaugeDesk now pins the WhippleScript runtime with current-access checks and
  guarded native imports. Office upload integration remains in progress; this
  dependency update does not enable the office network listener.

- Native upload adapters support original-authority checks at file placement
  boundaries. Cross-device copies stay provisional until a final checked swap;
  refusal preserves the previous file. Staff responses also recheck the captured
  authority before returning from their product writer fence. Native work and
  resource publication can share one transaction; a refused native check stays
  terminal for that admission even if its process flag is restored.

- Streamed uploads publish resource metadata, the complete file binding, access
  events and the original command receipt together. Office staff publication
  rechecks the captured session; a failed publication leaves no partial grant.
- New chat policies use their project's signing authority. Existing policy
  epochs keep their original signer and verification root, including on hosted
  operation retries. Missing project signing custody refuses a new policy;
  it cannot substitute the host's key. Hosted servers must support the matching
  project admission protocol before this path is enabled.

- A provider linked on a desktop while you are signed in belongs to your
  account and reaches your other desktops: each of your trusted devices gets
  its own sealed copy, and the Hub keeps only copies it cannot open. A Codex
  or Grok sign-in refreshed on one desktop is refreshed once, and the others
  take the result. Unlinking it on one desktop unlinks it on all of them. This
  starts working once the Hub holds account provider links; until then a
  desktop keeps its links as before.

- On a desktop, an Agent's, project's or Panel's settings chat runs on the
  same OpenAI or Codex access as that account's chats there. Before, it looked
  for model access where nothing a desktop links is kept, and refused every
  message with "link OpenAI or Codex model access in Account Settings" while
  chats worked.

- Running project workflows, saving files, and reading their history require
  owning the project or holding an explicit project grant. Tracker access and
  assignment recipients require current project standing as well as any tracker
  permissions. Organization owner/admin roles alone grant none of this access;
  ownership and grant changes take effect without restarting the Home. An
  account owner needs no organization membership; legacy organization-issued
  project grants still require an active directory recipient. Source and
  resource policies continue to apply.

- Prepared native workflow, tracker and file-correction operations using an
  account session are refused after that session or its device is revoked.
  Unattended workflow authority remains scoped to its retained launch.

- A project you own can be shared with anyone by email: Project settings →
  People & sharing makes an invitation link for an address, and only an
  account that has verified that address can accept it. An organization's
  projects still go to its members only, until an owner allows invitations by
  email under Organization Policy → Project sharing.

- Projects made on a desktop without signing in can be moved to the account
  you are signed in as: the account menu offers **Move signed-out projects to**
  that account, lists each project to move or leave behind, and moves them
  with their chats. The signed-out Personal project always stays.

- Signing in to ChatGPT / Codex from a hosted Home or the Hub no longer needs
  the Codex CLI: GaugeDesk speaks OpenAI's device-code sign-in itself. A Home
  or Hub without `codex` installed now offers a code instead of failing.

- A project can be forked from its menu: the fork is a new project of your
  own with the original's files and Agents, and none of its people, chats,
  credentials or deployments. Project settings → Work & data shows what a fork
  came from and pulls the original's later changes, asking you to keep your
  version or take theirs for any file both changed.

- "test in a chat" on an Agent in the Workshop runs the draft as it stands,
  without publishing, in a chat of its own with its own empty files. The chat
  sits under the Agent beside its edit chats, and testing again replaces it
  with one running the latest draft. Before, it ran the published version in
  Personal, and on a Personal holding more than one target it opened nothing.

- Native chat runtimes verify the policy's original signer and public key
  independently of the runtime actor. A harness factory carries public
  verification evidence without retaining a private governance signing key.

- Multi-target settlement signs new effect and recovery receipts with project
  authority. Existing host-signed receipts retain their original identity.
  Missing project signing custody stops new work before target effects start;
  historical verification uses public roots. Upgrade hosts before using the
  new project receipt frames in forward compensation.

- GaugeApp command projection callbacks receive their domain records' exact
  admitted positions, so a delayed project update cannot replace a newer one.
  Implementations constructing `gaugeapp_host::Applied` must accept the
  additional ordered position slice in `committed`; receipt and audit positions
  are excluded, and command retries still invoke no callback.

## [0.7.1] — 2026-10-05

- Native chat test evidence matches file writes through the folder binding
  recorded for that turn, so admitted folder names and the file viewer's stable
  paths identify the same synthetic file.

- Hosted project requests and listings now require account ownership or an
  explicit project grant. Organization owner and admin roles do not provide
  project data access. Legacy ownership follows the original computer claim,
  rather than the directory's current owner role.

## [0.7.0] — 2026-10-05

- Native file saves and corrections use project signing authority for new acts.
  Older commands and signed evidence keep their original identities on retry;
  current membership and project authority still govern each use.
  Upgrade older hosts before reading the new native signature frames.

- Reading recorded file history now checks that its original policy belongs to
  the admitted project and has a matching preparation receipt.

- Project workflows now use a retained project signing key. Moving a project
  carries that identity securely so its workflows can resume after the move.
  Upgrade the receiving host before moving a project with new workflows;
  older hosts refuse the new handoff format.

- Registered project gates now require a matching product acknowledgment before
  using an imported program. Missing or mismatched Home journals stop that work
  instead of falling back to the install-wide prototype.

- Added durable, project-bound operation journal storage for Homes. Missing or
  replaced journal files refuse reopening; production path integration remains
  in progress.

## [0.6.1] — 2026-10-02

- WhippleScript programs now run on Wasmtime 48.0.5, which fixes seven
  advisories published on 2026-10-02 (RUSTSEC-2026-0321 to -0327), among them a
  native stack buffer overflow and two kinds of GC heap corruption.

- On a desktop shared by more than one account, each account now has its own
  Personal, its own Agents, and its own provider credentials, logins,
  TokenWright boxes and model settings. Before, every account's quick-start
  chats landed in one Personal and every account linked into and ran on one
  set of credentials. The account that claimed the computer keeps everything it
  held, including Agents with no recorded owner; another account signs in to
  its providers once.

- Crypto admission guards have four finite Quint oracles paired with real core
  predicate fixtures. Their probes must produce invariant counterexamples.

- The weekly TokenWright integration lane runs on the fleet at the compatibility
  pin. Its matching forge job is retired after the fleet passed all eight tests.

- The TokenWright integration check has a reusable fleet command that runs the
  shipped client against the exact compatibility pin and refuses skipped tests.

- The development and preview servers proxy the full inventoried control-plane
  surface, including tutorial launches. The route check now refuses a missing
  proxy prefix when a backend route is added.

- GaugeDesk in a browser can now open, edit and upload files, read and change a
  chat's configuration, and preview a merge on a Home it reaches through the
  relay, such as a desktop at home. Before, each of these failed with "Home raw
  transport unavailable".

- Existing Agent drafts that can read files gain `offer_download`, so they can
  offer a file from `artifacts/` in the chat. Published versions stay unchanged;
  publish the updated draft to give an existing placement or deployment the tool.

- Hosted clients avoid desktop-only account-session and federation reads. Projects
  without a published route reuse their selected Home connection instead of
  repeatedly reading account directory discovery.

- GaugeApp agents now remember the recent admitted exchanges in their exact
  management conversation when you send a follow-up. Clearing the conversation
  starts their context fresh.

- In the hosted Console you can open your work chats' files again, the
  agent's output included, and Files lists them. Since 2026-09-28 every file
  nobody had granted you was withheld, your own work with it. A file another
  person uploaded into a shared chat still needs their approval.

## [0.6.0] — 2026-10-02

- A Panel session now has a folder each for the visitor, the agent and you.
  The visitor sees what the agent puts in `artifacts/`, in the Files panel,
  which now offers Download beside Open. `work/` is the agent's own and is
  never shown, and only files under `outbox/` can be collected into your
  Inbox. The download card in the chat is gone, so a deployment that shows
  only the chat offers the visitor no files, and `deliverable/` is no longer
  offered at all. An embedded PDF or image now opens, and a binary file now
  downloads; before, every such read was refused.

  This breaks Panel agents that collect files. One whose "Files to collect"
  names `artifacts/`, as 0.5.3 required, can no longer be saved, published
  or deployed. Change it to a path under `outbox/`, have the agent write what
  you should receive there (and what the visitor should download to
  `artifacts/`, with the Files panel on), and publish a new version.
  Deployments already running keep collecting as before.

- An operator can send GaugeWright-funded GaugeApp agent turns to a Responses
  endpoint other than OpenAI's, such as an AI gateway in front of it, with
  `GAUGEDESK_MANAGEMENT_AGENT_ENDPOINT`. It must be HTTPS, or HTTP on a
  loopback address, and only the managed key is sent there; a person's own
  linked OpenAI credential still goes to OpenAI.
- A connection through the relay that stops reading no longer puts every
  other connection to the same Home at risk. Desktops, phones and browsers
  now tell the relay what they have taken, and when a Home's relay runs short
  of buffer space it closes the connections that have fallen furthest behind,
  which reconnect, instead of letting one stalled reader exhaust it for all.
- A Home reached through the relay serves up to 1,024 connections at once
  instead of 16, and hangs up on a caller it has refused before knowing who
  they are, so someone who has only the Home's public relay address can no
  longer hold its connections open.
- A project whose gate screens inbound material with a model now screens. It
  uses the project's own OpenAI key if one is pinned, and otherwise the OpenAI
  key linked by the person running the screen or review. Before, it looked for
  a key in an account named after the project, never found one, and every
  screening pass failed. A project that reviews by hand still needs no key.
- GaugeDesk in a browser now updates live for a Home it reaches through the
  relay, such as a desktop at home. A message sent from the desktop app, and
  its reply, appear in an open browser tab as they happen instead of after a
  reload.
- Selecting an Agent in Workshop opens its settings and keeps its row
  selected, with a Settings chat in the chat lane that can explain and change
  its preferred model, its abilities and, for a Panel agent, its public
  profile. The Agent's edit chats stay rows under it. Deleting the Agent ends
  those conversations.
- Agent settings is a plain page, without the explanatory text under each
  control. The preferred model is a dropdown of the models you can reach, and
  every model dropdown names its default ("GPT-6.1 Sol (default)"). A Panel
  agent's public contract uses the same ability presets and model dropdown,
  so visitors' abilities are one of the four presets, plus Ask questions.
- A new Agent starts as Chat only: it can talk and ask you questions, but
  cannot read or write files or run commands until you choose a preset in its
  settings. Existing Agents and the Default agent are unchanged.
- Selecting a Panel placement opens Panel Settings for anyone in its project,
  not only the Agent's author. It shows the pinned version and its public
  profile, the placement's deployments, what they returned to the Inbox, and
  a Settings chat. Before, it did nothing unless you had authored the Agent.
- An item you keep from an Inbox now reaches the project's work chats started
  afterwards, at `inbound/` in the project folder. Before, it was written to
  disk and no chat ever saw it.
- Reopening a deployment shows its full embed code, with the loader script
  and panel elements. Before, it showed a bare `<gw-session>` tag that
  rendered nothing where it was pasted.
- The top bar's inbound count now appears for a project with items waiting on
  a person even when it has no chat, such as a project whose only placement
  is a Panel placement. It opens the project's Inbox, or the placement's
  Inbox in Panel Settings when every item came from that placement, and it
  updates as soon as you keep or flag one. On the phone it is a note in the
  queue.
- A chat keeps its conversation when its Agent changes underneath it. A work
  chat whose placement moves to a new Agent version, or an edit chat after
  its editor is updated, carries on and answers under the new version.
  Before, the model lost the whole conversation while the transcript still
  showed it.
- An Agent's edit chat now knows what it is editing. It explains the Agent's
  files and when each is loaded, treats them as material rather than as
  instructions to follow, and has WhippleScript's authoring guide and
  examples to hand. Try the Agent's behaviour with "test in a chat".
- A project now records the account that created it. On the desktop, a
  signed-in account sees and opens only the projects it owns or was given
  access to; an owner or admin role no longer reaches every project on the
  computer. Projects from before this release belong to the account that
  claimed the computer, so its view is unchanged.
- On a managed Project Host, the Compute policy dialog reads and saves the
  Isolated workspace policy on the host's own Home, the one its turns
  enforce, and shows that Home's prices and limit per attempt. Only the
  organization's owner can change it; other members see it read-only.
  Before, it saved a copy on the Hub that no turn enforced. Without a
  connection to the Home, the dialog no longer offers the policy.
- In Commercial Operations, a product can be retired, which takes it out of
  the Products list and the new-proposal picker while its engagements carry
  on, and restored from the retired view. A product that no engagement uses
  can be deleted, after review.
- The Agent improvement campaign controls and hosted comparison routes have
  been removed. Agent editing, preview, publishing, and placement remain
  available; WhippleScript's standalone `improve` function is unaffected.

- The model picker offers the current models: Claude Fable 5.1, Opus 5.5,
  Sonnet 5.5 and Haiku 4.5; GPT-6 Astra, 6.1 Sol and Luna; and Grok 4.7. A
  model that a newer one in its line has replaced, such as Claude Opus 4.7 or
  GPT-5.5, is hidden until you enable it under "Models in the picker", and a
  chat already using one keeps it. Retired models are gone: Claude 3.x,
  Claude Opus 4.1, Claude Haiku 3, and GPT-5.4 for a Codex sign-in.
- A chat that pins no model now runs GPT-6.1 Sol when you are signed in to
  Codex. Before, it ran GPT-5.5, which Codex retires on 2026-10-14. With only
  an Anthropic, OpenAI or xAI key linked, it now runs Claude Opus 5.5, GPT-6.1
  Sol or Grok 4.7, billed to that key, instead of asking you to pick a model.
  A Panel agent that pins no model publishes with the same default, so pin a
  model if you want a cheaper one for visitors.

- A chat's messages offer copy and fork as small icons in place of the "Fork
  here" button, and each agent turn shows the time it finished. Turns from
  before this release show no time.
- The Projects filter menu opens rightward from its button instead of past
  the window's left edge.
- Hover help across the app appears in a quarter of a second, in the app's
  own type and colours, instead of the browser's slower, smaller tooltip.
- When something you do in the workbench fails, such as starting a chat,
  setting the model, forking, attaching files or keeping a change, the
  failure now shows as a dismissable message in the pane where you did it.
  Before, it was recorded nowhere you could see, so the control seemed to do
  nothing. A first message sent from the empty chat whose chat could not be
  started goes back into the box instead of disappearing.
- The Files pane follows changes made while you look elsewhere: a turn that
  finished in another chat, work synced in from another chat, or a tool
  writing mid-turn. Before, it kept showing the old files until you
  reselected the chat.
- A Panel agent's name uses the nav row's full width. The redundant "open"
  button beside its ⋯ menu is gone; the row itself opens the agent.
- The rail of your messages rests in the chat pane's margin instead of
  pushing the transcript over.

## [0.5.3] — 2026-10-01

- Signed in on the desktop, the workbench now opens on the selected account's
  own Workshop and Projects. In 0.5.1 and 0.5.2 it could first list the Local
  account's Agents and keep them, so opening one did nothing or failed with
  "Agent authoring is unavailable to this account". That work is still in the
  Local account, which you can select from the account menu. A Panel agent that
  cannot be opened now says why.

## [0.5.2] — 2026-10-01

- Multiple browser windows and devices can connect to one Home concurrently.
  Each session retains independent admission; closing one leaves the others
  connected. Relay failures identify the Home connection rather than blaming
  the account service.

- Hosted Agent improvement operation status now reports its own model token
  usage and reservation settlement counts, including after a worker retry.
- Chats expose the admitted folder names to the model, so a new file-writing
  turn can use the paths its tools accept. Provider failures retain their reason
  in the chat. Desktop publication now requires successful first and second
  file-writing turns and persistence after restarting each installed bundle.

## [0.5.1] — 2026-10-01

- A Panel agent's deployment now chooses its model provider from who pays for
  it: GaugeWright managed inference by default, or a provider key you store.
  Publishing on managed inference no longer requires typing the metered
  gateway's address into the agent's contract, and the contract's Model
  section offers your work-chat default or a pinned model instead of provider
  fields. An unpinned agent publishes with your work-chat default model
  (DR-0272).
- Try a Panel agent from its Workshop menu ("try in a preview chat") or a
  placement's ("preview this version"): a disposable work chat on your usual
  model and funding, listed under the agent. Deleting the chat ends it. The
  earlier public-edge preview is removed.
- The deploy dialog opens for a Panel agent whose Home runs an older GaugeDesk,
  instead of failing silently.
- A member limited to specific projects can no longer reach Home routes that
  name no project, apart from their own account, filtered listings and
  Home-wide settings such as the Isolated workspace policy (DR-0270).
- The desktop's local channel answers only its own window (DR-0269).
- A provider that is out of credit is reported as such, not as a failed request.
- A Panel agent's visitor model picker offers every catalog model.
- Workshop keeps existing local Agents and edit chats in the local account
  across sign-in and upgrades. Its listings and file access follow the selected
  account, and the desktop account menu names and opens the local account.
  Failed file reads now show an error with retry instead of staying on loading.

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
