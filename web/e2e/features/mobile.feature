Feature: Mobile projection client — pair, navigate, send (offline + online)

  The mobile flow harness (MOB-029) composes the committed D-MOBILE islands into
  the device's real journey over the live control plane: a device pairs to an
  environment (the MOB-027 boundary handshake), navigates the carousel one pane at
  a time (MOB-014/009), and may issue exactly one standing command — a send —
  which a degraded connection refuses with an explicit banner (MOB-028), never a
  silently dead control. The send re-enables when the device is back online.

  Background:
    Given the mobile client is open

  Scenario: a device pairs to an environment
    When I pair with the ticket "gaugewright-pair://demo-env/device:web-harness"
    Then the device is paired
    And the connection is active

  Scenario: a paired device navigates the carousel between panes
    Given I have paired with the ticket "gaugewright-pair://demo-env/device:web-harness"
    When I open the chat pane
    Then the chat composer is shown
    When I open the browse pane
    Then the paired environment is shown

  Scenario: a chat started on the device shows up on the desktop
    # The device and desktop are two clients of one control plane: a chat started on
    # the device must be the same kind the desktop's quick-start makes (a WORK chat,
    # not an edit chat) and appear in the desktop's Personal project — the cross-surface
    # flow that was silently broken (the device made edit chats the desktop hid).
    Given I have paired with the ticket "gaugewright-pair://demo-env/device:web-harness"
    When I start a new chat on the device
    Then it shows up as a work chat in the desktop's Personal project

  Scenario: send is refused offline and restored online
    Given I have paired with the ticket "gaugewright-pair://demo-env/device:web-harness"
    When I open the chat pane
    And I go offline
    Then the offline banner is shown
    And the composer refuses to send
    When I go online
    Then the offline banner is gone
    And I can send "do the work"

  Scenario: the human task queue is reachable from the top bar
    # mobile-client.md, "Top bar" → Next ③: the human task queue is a header
    # affordance (not a carousel stop). A finished turn queues a review; the badge
    # counts it, the ⌄ pull-down opens the full queue sheet (current-first), and a
    # tap jumps to that task's chat. Previously the phone surfaced no tasks at all.
    Given I have paired with the ticket "gaugewright-pair://demo-env/device:web-harness"
    When I start a new chat on the device
    And I request review for the next mobile change
    And I can send "make a change"
    Then the task queue badge appears
    When I open the task queue
    Then the task queue lists a review
    When I jump to the first task from the queue
    Then the chat composer is shown
