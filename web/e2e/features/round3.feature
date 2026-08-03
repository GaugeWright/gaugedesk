@transport
Feature: Honest discard, reachable settings, grouped chats (round 3)

  Round 3 closes feedback inconsistencies: discarding work tells the honest truth
  (you chose to throw it away — nothing "failed"), an archetype's settings open
  from its right-click menu, All chats groups by archetype instead of
  repeating the label per row, and the decorative version badge is gone.

  Scenario: discarding work shows one honest, plain-language end-state
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    And I open the "diff" tab
    And I discard the work
    Then the changes show an honest discarded state
    And I am offered to start over, not to fix it up

  Scenario: an archetype's settings open from its context menu
    Given the workbench is open
    When I create an archetype named "round3-method"
    And I click the settings link on the method "round3-method"
    Then the method settings modal is open

  Scenario: placements carry no decorative version badge
    Given a new engagement
    Then placements carry no version badge
