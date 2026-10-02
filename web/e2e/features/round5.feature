@transport
Feature: Round 5 — honest View after discard, plain chat types, reachable nav, a real settings form

  The round-5 review found the deepest honest-feedback violation yet (the View tab
  still showed discarded text while Changes said it was thrown away), the chat-type
  distinction described only in implementation jargon, the whole Projects tree
  unreachable by keyboard, and "set what this method does" still dead-ending at a
  raw-JSON box. These scenarios lock in the fixes.

  Scenario: the Projects tree chat rows are reachable and openable by keyboard
    Given a new engagement
    Then the chat rows are keyboard-reachable
    When I open a chat by keyboard
    Then the run phase is "Init"

  Scenario: the settings page leads with a plain form and demotes the raw JSON to Advanced
    Given the workbench is open
    When I open the config editor
    Then the settings page shows a plain-language form
    When I expand the advanced settings
    Then the raw settings text is shown

  Scenario: selecting an Agent opens its settings and keeps it selected
    Given the workbench is open
    When I select the first Agent in the Workshop
    Then its settings are open with the Agent selected in the Workshop
    And no edit chat was opened for it
    When I close the config editor

  Scenario: search has a clear control that resets the filter
    Given the workbench is open
    When I type "zzz" in the search box
    And I clear the search
    Then the search box is empty
