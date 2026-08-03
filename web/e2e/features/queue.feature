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

  Scenario: the stage-gate holds messages until released (#24)
    Given a new engagement
    When I enable the stage-gate
    And I queue the message "staged-one"
    And I queue the message "staged-two"
    Then the queue shows 2 messages
    And the run phase is "Init"
    When I release the stage-gate
    And the agent finishes
    Then the run phase is "Completed"

  Scenario: send now runs one held message immediately, ahead of the rest
    Given a new engagement
    When I enable the stage-gate
    And I queue the message "held-one"
    And I queue the message "held-two"
    Then the queue shows 2 messages
    And the run phase is "Init"
    When I send now the queued message "held-two"
    Then the agent is idle
    And the run phase is "Completed"
    And the queue shows 1 message
    When I open the "diff" tab
    Then the diff shows "held-two"
