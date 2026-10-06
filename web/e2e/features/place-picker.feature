@transport
Feature: Choosing what to place, and quieter power controls (round 2)

  Adding a method to a *named* project lets the user CHOOSE which method (a picker),
  rather than silently placing an arbitrary one. But placement is never a
  prerequisite for *trying* an Agent: its draft runs straight away in a disposable
  chat of its own, with no placement or publish step (DR-0324). A new chat takes its
  title from the first message instead of staying "new chat", and the hold/stage
  power control stays out of the way of the obvious "send".

  Scenario: adding a method to a named project opens a picker to choose which one
    Given the workbench is open
    When I create a project named "picker-co"
    And I open the add-method picker for project "picker-co"
    Then the place picker is open
    When I choose the first method in the picker
    Then the project "picker-co" shows its placements

  Scenario: an Agent is tested on its draft in a chat of its own
    Given the workbench is open
    When I test the archetype "Default" from its menu
    Then a test chat of its draft opens under it

  @chat-title
  Scenario: a new chat gets a fallback title when no model is configured
    Given a new engagement
    When I task the agent with "draft a spring campaign tagline"
    Then a chat titled "draft a spring campaign tagline" appears in the nav

  Scenario: messages can be held before they run
    Given a new engagement
    Then I can stash messages before running
