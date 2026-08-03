@transport
Feature: Tasking the agent

  As a user I task the agent and watch it work live; effects route through the
  boundary membrane, and I can review the diff and keep it.

  Scenario: the agent works in a worktree, streams, and the diff is kept
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    And a mediated tool line is shown
    And the chat log does not show "Finished this turn"
    When I click the tool target "agent-note.txt"
    Then the content viewer shows "agent-note.txt"
    When I open the "diff" tab
    Then the diff shows "agent-note.txt"
    When I keep the work
    Then the review is cleared from the task bar

  Scenario: stopping a running turn re-enables the composer
    Given a new engagement
    When I start tasking the agent with "[slow] long running task"
    Then the agent is working
    When I stop the turn
    Then the composer is ready to send again

  Scenario: a streaming tool line expands to show its detail (O2)
    Given a new engagement
    When I task the agent with "write a note"
    Then the run phase is "Completed"
    When I expand the first tool line
    Then the first tool line is expanded
