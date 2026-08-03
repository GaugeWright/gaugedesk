# @open-only: drives embed-example.html, which ships only in the open bundle —
# the enterprise-composition lane (GW_E2E_COMPOSITION=enterprise) skips it.
@open-only
Feature: Embedded panels (EMBED-2)

  As a consultant I embed the workbench panels as web components on my own page,
  driven by a scoped session over the deployment's control plane — the same panels
  the desktop renders, mounted against a remote Session (EMBED-1's contract).

  Scenario: the embedded chat renders and sends against a scoped session
    Given the embed example page is open
    Then the embedded chat shows a composer
    And the embedded chat uses the shared docked composer
    And the embedded panel set owns one attribution mark
    When I send "hello from the embed" in the embedded chat
    Then the embedded transcript shows "hello from the embed"

  Scenario: the embedded panels carry the workbench theme and accept --gw-* overrides
    Given the embed example page is open
    Then the embedded chat is themed by the workbench palette
    And a "--gw-bg" override cascades into the panel's shadow root

  Scenario: the Environment manifest gates which shared panels bind
    Given the chat-only embed Environment is open
    Then the embedded chat shows a composer
    And the unselected files and viewer panels are not composed

  Scenario: a block embed honors intentional sizing and grows its shared composer
    Given a block embedded chat sized by the panel min-height token is open
    Then the embedded chat uses the shared docked composer
    And the embedded message field grows with multiline text

  Scenario: every panel has resilient drop-in styling with deliberate overrides
    Given all embedded panels are open under broad hostile host styles
    Then every embedded panel keeps its structural defaults
    And every embedded panel exposes intentional styling hooks
    When the embedded panel host is mobile width
    Then every embedded panel fits without horizontal overflow
