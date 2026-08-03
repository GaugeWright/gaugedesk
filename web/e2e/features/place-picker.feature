@transport
Feature: Choosing what to place, and quieter power controls (round 2)

  Adding a method to a *named* project lets the user CHOOSE which method (a picker),
  rather than silently placing an arbitrary one. But placement is never a
  prerequisite for *using* an archetype: it is usable straight away in the hidden
  Personal project, with no placement step (ADR 0045/0036). A new chat takes its
  title from the first message instead of staying "new chat", and the hold/stage
  power control stays out of the way of the obvious "send".

  Scenario: adding a method to a named project opens a picker to choose which one
    Given the workbench is open
    When I create a project named "picker-co"
    And I open the add-method picker for project "picker-co"
    Then the place picker is open
    When I choose the first method in the picker
    Then the project "picker-co" shows its placements

  Scenario: an archetype is usable with no placement — a chat in Personal
    Given the workbench is open
    When I use the archetype "Default" from its menu
    Then a work chat opens

  Scenario: a new chat is titled from its first message
    Given a new engagement
    When I task the agent with "draft a spring campaign tagline"
    Then a chat titled "draft a spring campaign tagline" appears in the nav

  Scenario: the hold control sits inline beside send
    Given a new engagement
    Then I can hold messages before running
