Feature: Tuning the chat log

  The chat log brackets each agent turn (its prose + the tool calls it made) into
  one collapsible unit, splits tool calls into commands / writes / reads the filter
  can hide, and strips boilerplate confirmations ("wrote 1 file") so a disclosure
  reveals real output, not filler. All of it is pure view state over the same
  durable transcript.

  Scenario: an agent turn collapses to a one-line summary
    Given a new engagement
    When I task the agent with "make a change"
    Then a mediated tool line is shown
    And the chat log does not show "Finished this turn"
    When I collapse the first turn
    Then the first turn is collapsed
    And no tool line is shown

  Scenario: the filter hides a tool category without losing the others
    Given a new engagement
    When I task the agent with "make a change"
    Then a mediated tool line is shown
    When I hide "write" tool calls from the chat log
    Then no "write" tool line is shown
    And a mediated tool line is shown

  Scenario: a file write is a tight line with no boilerplate confirmation
    Given a new engagement
    When I task the agent with "make a change"
    Then a mediated tool line is shown
    And the chat log does not show "wrote 1 file"

  Scenario: saving the filter as default persists it across a reload
    Given a new engagement
    When I task the agent with "make a change"
    Then a mediated tool line is shown
    When I hide "write" tool calls from the chat log
    And I save the filter as default
    And I reload the workbench
    And I switch to the "Projects" facet
    And I reopen the chat
    Then no "write" tool line is shown
    And a mediated tool line is shown
