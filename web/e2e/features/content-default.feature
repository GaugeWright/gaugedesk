@transport
Feature: Content viewer opens on View unless a review is open

  The third-column content viewer defaults to the file View. The Changes (diff)
  surface leads only when the chat has a candidate awaiting keep/discard (a
  "Clean" merge phase) — which, since ADR 0136 retired the per-change hold, means
  a chat on an attached target rather than an auto-syncing managed one. A chat
  with nothing pending should not open on Changes.

  The managed-target half of that (a finished turn *not* taking over the view)
  has no scenario here: it needs an attached folder, and attaching one goes
  through a native desktop dialog this suite cannot drive.

  Scenario: a fresh chat with nothing to review opens on View
    Given the workbench is open
    When I start a new chat in Personal
    Then the content viewer is on the "view" tab
