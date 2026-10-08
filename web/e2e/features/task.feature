@transport
Feature: Tasking the agent

  As a user I task the agent and watch it work live; effects route through the
  boundary membrane, and I can read the diff of what it changed.

  Scenario: the agent works in a worktree, streams, and the diff is readable
    Given a new engagement
    When I task the agent with "make a change"
    Then the run phase is "Completed"
    And a mediated tool line is shown
    And the chat log does not show "Finished this turn"
    When I click the tool target "agent-note.txt"
    Then the content viewer shows "agent-note.txt"
    When I open the "diff" tab
    Then the diff shows "agent-note.txt"

  Scenario: stopping a running turn ends it and re-enables the composer
    Given a new engagement
    When I start tasking the agent with "[hold] until I stop it"
    Then the agent is working
    When I stop the turn
    Then the turn ends promptly
    And the composer is ready to send again

  # The button was covered along its leading edge by the delivery menu, which
  # opens on hover and whose rows are disabled with an empty draft — so a click
  # aimed at Stop hit a disabled row and did nothing at all, in silence.
  Scenario: the whole of the stop button is the stop button
    Given a new engagement
    When I start tasking the agent with "[hold] until I stop it"
    Then the agent is working
    When I aim at the stop button with the delivery menu open
    Then every part of the stop button reaches stop
    When I stop the turn
    Then the turn ends promptly

  # Stopping your own turn is not a fault and not a failed delivery: no error on
  # the composer, and the cancelled message is not handed back to be run again.
  Scenario: a stopped turn leaves no error, and what was queued behind it runs
    Given a new engagement
    When I start tasking the agent with "[hold] until I stop it"
    Then the agent is working
    When I queue the message "the follow-up"
    And I stop the turn
    Then the turn ends promptly
    And the composer shows no error
    And the agent finishes

  # Every scenario above presses Stop against a turn that already has something
  # to interrupt: the fake binds its hold in microseconds. A real turn spends
  # 124-222ms first — resolving a provider, prechecking a credential over the
  # network twice, taking the workbench lock, building a harness — and a Stop
  # landing in there was refused outright as "not interruptible" while the turn
  # ran on. That window existed only in the opt-in live lane, which costs tokens
  # and does not gate a merge, so nothing here could fail on it.
  #
  # `[startup]` reproduces the window in the lane that gates every merge. No
  # `[hold]`: the turn behind it is short, so a Stop that was dropped shows up
  # as a turn that *completed*, and the receipt is what tells the two apart.
  Scenario: a turn stopped before it reaches its harness still ends
    Given a new engagement
    When I start tasking the agent with "[startup] a turn to stop during startup"
    Then the agent is working
    When I stop the turn
    Then the stop is receipted as a cancellation
    And the turn ends promptly
    And the composer shows no error
    And the composer is ready to send again

  Scenario: Escape interrupts the running turn
    Given a new engagement
    When I start tasking the agent with "[hold] until I stop it"
    Then the agent is working
    When I press Escape in the composer
    Then the turn ends promptly

  # Escape dismisses the innermost thing it can, and goes no further: with a
  # composer menu open it closes the menu, and the turn keeps running.
  Scenario: Escape closes an open composer menu before it reaches the turn
    Given a new engagement
    When I start tasking the agent with "[hold] until I stop it"
    Then the agent is working
    When I open the composer mode menu
    And I press Escape in the composer
    Then the composer mode menu is closed
    And the agent is working
    When I press Escape in the composer
    Then the turn ends promptly

  Scenario: a streaming tool line expands to show its detail (O2)
    Given a new engagement
    When I task the agent with "write a note"
    Then the run phase is "Completed"
    When I expand the first tool line
    Then the first tool line is expanded
