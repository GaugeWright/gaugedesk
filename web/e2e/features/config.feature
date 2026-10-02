@transport
Feature: Archetype settings

  GaugeDesk owns runtime selection; the WhippleScript package owns behavior and
  tools. Invalid settings and attempts to put package policy here are rejected.

  Scenario: save a valid config
    Given the workbench is open
    When I open the config editor
    And I set the config to "{\"model\":\"gpt-5.5\"}"
    Then the config status shows "saved"

  Scenario: reject a malformed config with a plain-language message
    Given the workbench is open
    When I open the config editor
    And I set the config to "{ not valid json"
    Then the config status shows "isn't valid"

  Scenario: reject package authority in GaugeDesk runtime settings
    Given the workbench is open
    When I open the config editor
    And I set the config to "{\"policy\":{\"block_tools\":[\"bash\"]}}"
    Then the config status shows "package-owned"

  Scenario: an archetype's settings open from its context menu
    Given the workbench is open
    When I create an archetype named "round3-method"
    And I click the settings link on the method "round3-method"
    Then the method settings page is open

  Scenario: runtime settings stay outside the target workspace
    Given a new engagement
    When I reveal the internal files
    Then the target workspace does not contain ".agent-config.json"

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
