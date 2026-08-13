@transport
Feature: Send queue & steering

  While the agent is working I can stack follow-up messages on top of the
  composer. Queued messages are reorderable, editable, and cancellable, and they
  drain in order when each turn settles. Steering sends now, jumping the queue.

  Scenario: queued messages stack, then edit, cancel, and drain in order
    Given a new engagement
    When I start tasking the agent with "[slow] alpha"
    Then the agent is working
    When I queue the message "beta"
    And I queue the message "gamma"
    Then the queue shows 2 messages
    When I cancel the queued message "beta"
    Then the queue shows 1 message
    When I edit the queued message "gamma" to "gamma-edited"
    And the agent finishes
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the diff shows "alpha"
    And the diff shows "gamma-edited"

  Scenario: queued messages reorder by drag
    Given a new engagement
    When I start tasking the agent with "[slow] one"
    Then the agent is working
    When I queue the message "two"
    And I queue the message "three"
    Then queued message 1 is "two"
    When I drag queued message "three" above "two"
    Then queued message 1 is "three"
    And the agent finishes

  Scenario: steering jumps the queue and runs now
    Given a new engagement
    When I start tasking the agent with "[slow] original"
    Then the agent is working
    When I steer with "redirect"
    And the agent finishes
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the diff shows "redirect"

  Scenario: queue mode is set before the turn it governs, and holds through it
    Given a new engagement
    When I set the composer mode to "queue"
    And I start tasking the agent with "[slow] alpha"
    Then the agent is working
    When I send the message "beta"
    Then the queue shows 1 message
    And the agent finishes
    And the run phase is "Completed"

  Scenario: stash mode puts what Enter sends into the queue, held (#24)
    Given a new engagement
    When I set the composer mode to "stash"
    And I send the message "staged-one"
    And I send the message "staged-two"
    Then the queue settles to 2 held messages
    And the run phase is "Init"
    When I release the held message "staged-one"
    And I release the held message "staged-two"
    And the agent finishes
    Then the run phase is "Completed"

  Scenario: a held message does not hold up the ones meant to run
    Given a new engagement
    When I stash the message "jotted for later"
    And I start tasking the agent with "[slow] the real work"
    Then the agent is working
    When I queue the message "the follow-up"
    Then the queue shows 2 messages
    And the queue settles to 1 held message

  Scenario: send now runs one held message immediately, ahead of the rest
    Given a new engagement
    When I stash the message "held-one"
    And I stash the message "held-two"
    Then the queue shows 2 messages
    And the run phase is "Init"
    When I send now the queued message "held-two"
    Then the agent is idle
    And the run phase is "Completed"
    And the queue shows 1 message
    When I open the "diff" tab
    Then the diff shows "held-two"
