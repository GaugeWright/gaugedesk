@transport
Feature: Multi-turn conversation

  An engagement is a persistent conversation, not one-shot tasks: it holds one
  WhippleScript thread across turns, so work accumulates and context carries.

  Scenario: work accumulates across turns
    Given a new engagement
    When I task the agent with "first task"
    And I task the agent with "second task"
    Then the run phase is "Completed"
    When I select the file "agent-note.txt" in the workspace
    And I open the "view" tab
    Then the file view shows "first task"
    And the file view shows "second task"

  @live-provider
  Scenario: the conversation remembers across turns
    Given a new engagement
    When I task the agent with "Remember the number 4273. Acknowledge only, do not use tools."
    And I task the agent with "What number did I ask you to remember? Reply with just the number and use no tools."
    Then the transcript shows "4273"

  Scenario: the transcript survives a reload (durable, not client-only)
    Given a new engagement
    When I task the agent with "remember this message"
    Then the run phase is "Completed"
    When I reload the workbench
    And I switch to the "Projects" facet
    And I reopen the chat
    Then the transcript shows "remember this message"
