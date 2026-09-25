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
