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

  Scenario: a running turn says what the agent is doing, then gets out of the way
    Given a delayed embedded chat is open
    When I send "what is taking so long" in the embedded chat
    Then the embedded chat says the agent is thinking
    And the embedded activity row is announced politely
    When the delayed turn completes
    Then the embedded chat shows no activity row
    And the embedded transcript keeps the answer it streamed

  Scenario: a running tool is named rather than left unexplained
    Given a delayed embedded chat running the "bash" tool is open
    When I send "build it" in the embedded chat
    Then the embedded chat says the agent is thinking
    Then the embedded chat says the agent is running a command
    When the delayed turn completes
    Then the embedded chat shows no activity row

  Scenario: stopping a turn returns the indicator to rest
    Given a delayed embedded chat is open
    When I send "never mind" in the embedded chat
    Then the embedded chat says the agent is thinking
    When I stop the embedded turn
    Then the embedded turn is interrupted
    And the embedded chat shows no activity row

  # The two ways a stop was unreachable in the workbench (#310) are both in the
  # shared composer, so a visitor inherits them or inherits their repair. The
  # embed renders in a shadow root, which is its own reason to check rather than
  # assume: nothing about the desktop's geometry carries across on its own.
  Scenario: Escape interrupts the embedded turn
    Given a delayed embedded chat is open
    When I send "never mind" in the embedded chat
    Then the embedded chat says the agent is thinking
    When I press Escape in the embedded composer
    Then the embedded turn is interrupted
    And the embedded chat shows no activity row

  Scenario: the whole of the embedded stop button is the stop button
    Given a delayed embedded chat is open
    When I send "never mind" in the embedded chat
    Then the embedded chat says the agent is thinking
    When I aim at the embedded stop button with the delivery menu open
    Then every part of the embedded stop button reaches stop

  Scenario: stopping a turn cancels the work it had already scheduled
    Given a delayed embedded chat running the "bash" tool is open
    When I send "never mind" in the embedded chat
    Then the embedded chat says the agent is thinking
    When I stop the embedded turn
    Then the embedded chat stays at rest through the stopped turn's schedule

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
    Then the embedded turn is not interrupted
    And the embedded runtime admits commands in the order "follow_up:second request,steer:urgent correction"
    And the commands join the current turn rather than starting another
    And the embedded durable queue eventually drains

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
