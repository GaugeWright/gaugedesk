@transport
Feature: Personal-project "just start typing" quick-start

  Personal is the explicit zero-setup project (ADR 0097). Its "+ new chat"
  affordance roots a work chat on its default placement (ADR 0035) without setup.

  Scenario: the empty chat pane starts a Personal chat with the first message
    Given the workbench is open
    Then the empty chat composer is ready
    When I task the agent with "draft a welcome note"
    Then the active chat is a work chat
    And I see a chat in Personal

  Scenario: a new chat in Personal opens a work chat with no setup
    Given the workbench is open
    When I start a new chat in Personal
    Then the run phase is "Init"
    And the active chat is a work chat
    And I see a chat in Personal
