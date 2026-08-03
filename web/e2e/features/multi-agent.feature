@transport
Feature: Multiple agents run concurrently with per-chat state (round-13)

  The workbench drives each chat independently, so two chats can run turns at the
  same time. Each chat owns its run state — a status dot in the Browse panel — and a
  background turn must never clobber the chat that is on screen.

  Scenario: two chats run at once, with independent dots and no cross-talk
    Given a placement I can open more chats under
    When I start tasking the agent with "[slow] task alpha"
    Then the open chat shows a working dot
    When I open another chat under that placement
    And I start tasking the agent with "[slow] task beta"
    Then 2 chats show a working dot
    And the chat pane shows "task beta" but not "task alpha"
    When the running turns finish
    Then no chat shows a working dot
