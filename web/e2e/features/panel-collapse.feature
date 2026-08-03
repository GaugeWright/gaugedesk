@transport
Feature: Collapsible workbench panels

  Every panel — browse, chat, content, and files — folds to a thin rail to
  give the rest of the workbench more room. Collapse is a browser-local
  preference, so a folded panel stays folded across a reload (§4).

  Scenario: folding the browse panel leaves a rail that reopens it
    Given the workbench is open
    Then the "Browse" panel is open
    When I collapse the "Browse" panel
    Then the "Browse" panel is folded
    When I expand the "Browse" panel
    Then the "Browse" panel is open

  Scenario Outline: each side panel folds and unfolds
    Given the workbench is open
    When I collapse the "<panel>" panel
    Then the "<panel>" panel is folded
    When I expand the "<panel>" panel
    Then the "<panel>" panel is open

    Examples:
      | panel   |
      | Browse  |
      | Content |
      | Files   |

  Scenario: the chat panel folds and unfolds like the others
    Given the workbench is open
    Then the "Chat" panel is open
    When I collapse the "Chat" panel
    Then the "Chat" panel is folded
    When I expand the "Chat" panel
    Then the "Chat" panel is open

  Scenario: a folded panel stays folded across a reload
    Given the workbench is open
    When I collapse the "Files" panel
    Then the "Files" panel is folded
    When I reload the workbench
    Then the "Files" panel is folded
