@transport
Feature: Content viewer offers modes for available content

  The third-column header stays quiet before a file or review is available.
  File modes appear for the selected file's format and edit permission; Changes
  appears when the chat has a change to review.

  The managed-target half of that (a finished turn *not* taking over the view)
  has no scenario here: it needs an attached folder, and attaching one goes
  through a native desktop dialog this suite cannot drive.

  Scenario: a fresh chat without content shows only the pane name
    Given the workbench is open
    When I start a new chat in Personal
    Then the content header says only CONTENT

  Scenario: the split diff toggle is hidden when the review panel is too narrow
    Given a new engagement
    When I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the split diff toggle is not offered at the default panel width

  Scenario: runtime settings never enter the target review
    Given a new engagement
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the changed-files review hides the internal settings file
    And the review offers no internal-file toggle

  Scenario: the changes header has no hidden runtime-config disclosure
    Given a new engagement
    When I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the review offers no internal-file toggle
