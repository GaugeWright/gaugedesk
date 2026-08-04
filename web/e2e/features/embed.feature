# @open-only: drives embed-example.html, which ships only in the open bundle —
# the enterprise-composition lane (GW_E2E_COMPOSITION=enterprise) skips it.
@open-only @ui-mocked
Feature: Embedded panels (EMBED-2)

  As a consultant I embed the workbench panels as web components on my own page,
  driven by a scoped session over the deployment's control plane — the same panels
  the desktop renders, mounted against a remote Session (EMBED-1's contract).

  Scenario: the embedded chat renders and sends against a scoped session
    Given the embed example page is open
    Then the embedded chat shows its configured opening message
    And the embedded chat shows its configured agent name
    Then the embedded chat shows a composer
    And the embedded chat uses the shared docked composer
    And the embedded panel set owns one attribution mark
    When I send "hello from the embed" in the embedded chat
    Then the embedded chat still shows its configured opening message
    Then the embedded transcript shows "hello from the embed"

  Scenario: an anonymous embedded chat can start a fresh session
    Given an anonymous embedded chat is open
    Then the embedded chat shows a new session action
    When I start a new embedded session
    Then the embedded chat requests a fresh session

  Scenario: conversational prose renders safe GitHub-flavored Markdown
    Given the embed example page is open
    When I send a Markdown message in the embedded chat
    Then the embedded transcript renders its formatting without page overflow

  Scenario: a pasted image becomes native model input
    Given the embed example page is open
    When I paste a PNG image into the embedded chat
    Then the embedded composer shows the pasted image
    When I send the pasted image in the embedded chat
    Then the embedded turn carries the pasted image bytes

  Scenario: the paperclip admits supported files through the shared controller
    Given the embed example page is open
    When I attach a text file with the embedded paperclip
    Then the embedded composer shows the attached text file
    When I send the attached text file in the embedded chat
    Then the embedded turn carries the attached text

  Scenario: an embedded visitor can queue, steer, and stop through the shared controller
    Given a delayed embedded chat is open
    When I send "first request" in the embedded chat
    Then the embedded composer offers steer, queue, and stop
    When I queue "second request" in the embedded chat
    Then the embedded queue shows "second request"
    When I steer the embedded chat with "urgent correction"
    Then the embedded turn is interrupted
    And the embedded turns begin in the order "first request,urgent correction"
    And the embedded queue eventually drains in the order "first request,urgent correction,second request"

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
