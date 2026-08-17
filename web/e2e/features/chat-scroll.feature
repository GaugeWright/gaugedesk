@transport
Feature: The chat log's reading position

  The reading position belongs to the reader (transcript-scroll.ts). Sending a
  message anchors it near the top of the log with room reserved below so the
  reply streams in under it without moving the viewport, and a jump-to-latest
  button offers the way back to the live end whenever transcript sits below
  the fold.

  Scenario: sending anchors my message near the top with room reserved below
    Given a new engagement
    When I task the agent with "make a change"
    And I task the agent with "make another change"
    Then the transcript echoes my message "make another change"
    And my sent message is anchored near the top of the chat log
    And blank room is reserved under the conversation

  Scenario: the jump-to-latest button returns me to the live end
    Given a new engagement
    When I task the agent with "make a change"
    And I task the agent with "make another change"
    And I wheel the chat log to the top
    Then a jump-to-latest button is offered
    When I jump to the latest
    Then the chat log rests at its end
    And no jump-to-latest button is offered
