Feature: Round 7 — a layout that fits, a pinned composer, and immediate feedback

  The round-7 review found the shell broke at ordinary laptop sizes (the SEND
  button clipped, a horizontal scrollbar), the composer scrolled out of view on a
  short window, the View tab sat empty while Changes auto-rendered the same file,
  and a turn blinked to "done" with no echo of what the user just asked. These
  scenarios lock in the fixes.

  Scenario: the send button stays fully visible at a narrow laptop width
    Given a new engagement
    When the window is a narrow laptop size
    Then the send button is fully on screen

  Scenario: the composer stays pinned even with a long transcript on a short window
    Given a new engagement
    When the window is a short frame
    And I task the agent with "add a closing line"
    Then the send button is fully on screen

  Scenario: a long message wraps and grows without taking over the Chat panel
    Given a new engagement
    Then the message field wraps, grows, and stops at half the Chat panel

  Scenario: View auto-opens the file a turn just changed
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the run phase is "Completed"
    When I open the "view" tab
    Then the file view shows "agent-note"

  Scenario: sending echoes my message immediately
    Given a new engagement
    When I start tasking the agent with "write a haiku about cats"
    Then the transcript echoes my message "write a haiku about cats"
