@transport
Feature: Round 5 — honest View after discard, plain chat types, reachable nav, a real settings form

  The round-5 review found the deepest honest-feedback violation yet (the View tab
  still showed discarded text while Changes said it was thrown away), the chat-type
  distinction described only in implementation jargon, the whole Projects tree
  unreachable by keyboard, and "set what this method does" still dead-ending at a
  raw-JSON box. These scenarios lock in the fixes.

  Scenario: after a discard, the View tab honestly explains the file still shows the unkept changes
    Given a new engagement
    When I request review for the next change
    And I task the agent with "Add a friendly greeting"
    Then the run phase is "Completed"
    When I open the "diff" tab
    And I discard the work
    Then the changes show an honest discarded state
    When I open the "view" tab
    And I select the file "agent-note.txt" in the workspace
    Then the View tab explains the discarded changes are still on the private copy

  Scenario: the Projects tree chat rows are reachable and openable by keyboard
    Given a new engagement
    Then the chat rows are keyboard-reachable
    When I open a chat by keyboard
    Then the run phase is "Init"

  Scenario: the settings modal leads with a plain form and demotes the raw JSON to Advanced
    Given the workbench is open
    When I open the config editor
    Then the settings modal shows a plain-language form
    When I expand the advanced settings
    Then the raw settings text is shown

  Scenario: Escape closes the settings modal
    Given the workbench is open
    When I open the config editor
    And I press Escape
    Then the settings modal is closed

  Scenario: search has a clear control that resets the filter
    Given the workbench is open
    When I type "zzz" in the search box
    And I clear the search
    Then the search box is empty
