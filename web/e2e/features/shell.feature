Feature: The workbench shell

  As a user I see the four-panel workbench with a project-first facet browser,
  so I can orient myself across projects, the library of archetypes, and every
  chat (ADR 0035/0036).

  Scenario: the facet browser pivots by Recent, Projects, and Library
    Given the workbench is open
    Then the facet "Projects" is active
    And the facet "Recent" is present
    And the facet "Library" is present

  Scenario: Recent is a flat chat lens with explicit lineage
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    And I switch to the "Recent" facet
    Then Recent shows a chat in project "Personal" with archetype "Default" and workstream "sprint"
    And Recent shows no workstream groups

  Scenario: Recent chats use their rooted chat menu
    Given a new engagement
    Then Recent uses the same menu as the chat's rooted row

  Scenario: the search box filters across the facet (navigation.md B2)
    Given the workbench is open
    When I create an archetype named "Zephyr"
    Then I see the archetype "Zephyr"
    And I see the archetype "Default"
    When I search the facets for "Zeph"
    Then I see the archetype "Zephyr"
    And the archetype "Default" is hidden
    When I clear the facet search
    Then I see the archetype "Default"

  Scenario: the panels are labelled Chat and Files
    Given the workbench is open
    Then the run pane is labelled "Chat"
    And the workspace pane is labelled "Files"

  Scenario: only Content and Files fold from their left edge
    Given the workbench is open
    Then the "Content" panel collapse control is on the left edge
    And the "Files" panel collapse control is on the left edge
    And the "Browse" panel collapse control is on the right edge
    And the "Chat" panel collapse control is on the right edge
    And the "Content" panel collapse control faces "right"
    And the "Files" panel collapse control faces "right"
    And the "Browse" panel collapse control faces "left"
    And the "Chat" panel collapse control faces "left"

  Scenario: collapsing a project folds and unfolds its placements
    Given the workbench is open
    When I create a project named "collapsible"
    And I place an archetype on the project "collapsible"
    Then the project "collapsible" shows its placements
    When I collapse the project "collapsible"
    Then the project "collapsible" hides its placements
    When I collapse the project "collapsible"
    Then the project "collapsible" shows its placements

  Scenario: collapsing a placement folds and unfolds its chats
    Given the workbench is open
    When I create a project named "placefold"
    And I place an archetype on the project "placefold"
    And I add a work chat in project "placefold"
    Then the placement in project "placefold" shows a chat
    When I collapse the placement in project "placefold"
    Then the placement in project "placefold" hides its chats
    When I collapse the placement in project "placefold"
    Then the placement in project "placefold" shows a chat
