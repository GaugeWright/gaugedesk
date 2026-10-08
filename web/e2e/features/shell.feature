@transport
Feature: The workbench shell

  As a user I see the four-panel workbench with a project-first facet browser,
  so I can orient myself across projects, the library of archetypes, and every
  chat (ADR 0035/0036).

  Scenario: the facet browser pivots by Recent, Projects, and Workshop
    Given the workbench is open
    Then the facet "Projects" is active
    And the facet "Recent" is present
    And the facet "Workshop" is present

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

  Scenario: pane labels give way to content modes when content is available
    Given the workbench is open
    Then the browse pane opens with the facet tabs and no caption
    And the run pane is labelled "Chat"
    And the content pane is labelled "Content"
    And the workspace pane is labelled "Files"
    When I start a new chat in Personal
    Then the run pane's caption gives way to the chat's branch and kind
    And the content header says only CONTENT
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

  Scenario: the Projects tree chat rows are reachable and openable by keyboard
    Given a new engagement
    Then the chat rows are keyboard-reachable
    When I open a chat by keyboard
    Then the run phase is "Init"

  Scenario: search has a clear control that resets the filter
    Given the workbench is open
    When I type "zzz" in the search box
    And I clear the search
    Then the search box is empty

  Scenario: the selected chat row shows the chat's own name
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the selected chat row shows the title "draft a tagline for spring"

  Scenario: renaming a chat updates its selected row live (event-driven)
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the selected chat row shows the title "draft a tagline for spring"
    When I rename the open chat to "Spring campaign"
    Then the selected chat row shows the title "Spring campaign"

  Scenario: live search highlights the matched substring in a surviving row
    Given the workbench is open
    When I create an archetype named "Mailer"
    And I search the facets for "mail"
    Then the matched text "Mail" is highlighted in the results

  # navigation.md (Workshop): the toolbar keeps New Agent and Search on one line,
  # and New Agent is the facet's standing create action (ADR 0112 §3). It stands
  # above the search row rather than among the rows a search filters, so it
  # cannot read as a hit and is not withdrawn while a search is active.
  Scenario: the Workshop's New Agent stands beside Search, outside the results
    Given the workbench is open
    When I switch to the "Workshop" facet
    Then New Agent and Search share the Workshop toolbar line
    When I search the facets for "Default"
    Then I see the archetype "Default"
    And New Agent and Search share the Workshop toolbar line
    And New Agent stands above the search results
    When I clear the facet search
    Then New Agent and Search share the Workshop toolbar line

  Scenario: the chat lane keeps only one options button
    Given a new engagement
    Then the chat run state reads "Ready"
    And the chat lane has one options button
