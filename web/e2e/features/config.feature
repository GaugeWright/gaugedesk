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
