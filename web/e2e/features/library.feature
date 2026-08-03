@transport
Feature: The archetype & project library

  As a user I browse and manage archetypes (the Library of methods), projects,
  placements, and chats from the project-first facet browser (ADR 0035/0036) —
  created via affordances, edited via right-click context menus.

  Scenario: a fresh workbench seeds a default archetype
    Given the workbench is open
    When I switch to the "Library" facet
    Then I see the archetype "Default"

  Scenario: create an archetype and open an edit chat under it
    Given the workbench is open
    When I create an archetype named "reviewer"
    Then I see the archetype "reviewer"
    When I add an edit chat under the archetype "reviewer"
    Then the run phase is "Init"

  Scenario: a project places an archetype and hosts a work chat
    Given the workbench is open
    When I create a project named "client-site"
    Then I see the project "client-site"
    When I place an archetype on the project "client-site"
    And I add a chat under the placement
    Then the run phase is "Init"

  Scenario: one archetype placed on two projects (the many-to-many relation, C1)
    Given the workbench is open
    When I create a project named "alpha-site"
    And I place an archetype on the project "alpha-site"
    And I create a project named "beta-site"
    And I place an archetype on the project "beta-site"
    Then the project "alpha-site" shows its placements
    And the project "beta-site" shows its placements
    And the Library lists 3 archetype

  Scenario: delete an archetype via its context menu
    Given the workbench is open
    When I create an archetype named "scratch"
    Then I see the archetype "scratch"
    When I delete the archetype "scratch"
    Then the archetype "scratch" is gone

  # A workstream can be started from a chat in its explicit project, with no
  # root-picking — the placement resolves to the chat's own home and the chat joins
  # immediately, so the new shared line is a visible, non-empty group from the start.
  Scenario: create a workstream from a chat in Personal
    Given the workbench is open
    When I start a new chat in Personal
    Then I see a chat in Personal
    When I create a workstream named "sprint" from that chat
    Then the chat is on the workstream "sprint"

  # Leaving empties the line but does not delete it — the line stays visible (and
  # joinable) with an empty member list, no hint message (WS-H).
  Scenario: leaving a workstream empties it but keeps it visible with a hint
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    Then the chat is on the workstream "sprint"
    When I remove that chat from its workstream
    Then the workstream "sprint" shows it has no chats yet

  # Archiving closes the line for good: it disappears from the nav (only active lines
  # group chats) and its chat returns to the mainline list (WS-F INV-23 rehoming).
  Scenario: archiving a workstream removes the line and frees its chat
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    Then the chat is on the workstream "sprint"
    When I archive the workstream "sprint"
    Then there is no workstream "sprint"
    And I see a chat in Personal

  # A clean promoted line lands its work on Main, then retires and re-homes its chat.
  Scenario: promoting a workstream lands its work and retires the line
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    Then the chat is on the workstream "sprint"
    When I promote the workstream "sprint"
    Then there is no workstream "sprint"
    And I see a chat in Personal

  # A second chat in the same placement joins the existing line; only its co-rooted
  # lines are offered as targets.
  Scenario: a second Personal chat joins an existing workstream
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    Then the chat is on the workstream "sprint"
    When I start a new chat in Personal
    And I add the latest chat to the workstream "sprint"
    Then the workstream "sprint" has 2 chats

  Scenario: dragging a chat transfers it between workstreams
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "first" from that chat
    And I start a new chat in Personal
    And I create a workstream named "second" from that chat
    When I drag a chat from workstream "first" onto workstream "second"
    Then the workstream "first" shows it has no chats yet
    And the workstream "second" has 2 chats

  Scenario: dragging a chat onto Main leaves its workstream
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    And I drag a chat from workstream "sprint" onto Main
    Then the workstream "sprint" shows it has no chats yet

  Scenario: clicking away cancels an armed workstream merge
    Given the workbench is open
    When I start a new chat in Personal
    And I create a workstream named "sprint" from that chat
    And I arm merge for workstream "sprint"
    And I click away from the workstream merge
    Then workstream "sprint" merge is not armed

  # Per-placement config-only customization (placement.md): tweak a method for one
  # project/client without forking — a config overlay + notes on the placement, applied
  # to new chats there; the shared archetype is untouched.
  Scenario: customize a placement for one project without forking
    Given the workbench is open
    When I create a project named "AcmeCo"
    And I place an archetype on the project "AcmeCo"
    And I customize the placement in project "AcmeCo" with notes "AcmeCo prefers terse output"
    Then the placement in project "AcmeCo" shows it is customized

  # Fork lineage (ADR 0038): a fork shares its source's git history, shows the lineage,
  # and can pull the source's improvements down via a real 3-way merge.
  Scenario: a fork shows its source and can pull updates
    Given the workbench is open
    When I create an archetype named "base"
    And I fork the archetype "base"
    Then an archetype is forked from "base"
    When I pull updates into the fork of "base"
    Then an archetype is forked from "base"
