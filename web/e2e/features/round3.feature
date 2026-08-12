@transport
Feature: Honest discard, reachable settings, grouped chats (round 3)

  Round 3 closes feedback inconsistencies: an archetype's settings open from its
  right-click menu, All chats groups by archetype instead of repeating the label
  per row, and the decorative version badge is gone. (The honest-discard scenario
  went with ADR 0136 — a managed target auto-syncs, so there is no discardable
  candidate to reach it from here.)

  Scenario: an archetype's settings open from its context menu
    Given the workbench is open
    When I create an archetype named "round3-method"
    And I click the settings link on the method "round3-method"
    Then the method settings modal is open

  Scenario: placements carry no decorative version badge
    Given a new engagement
    Then placements carry no version badge
