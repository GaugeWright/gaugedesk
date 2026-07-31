Feature: Content viewer opens on View unless a review is open

  The third-column content viewer defaults to the file View. The Changes (diff)
  review surface leads only when the chat has a review open — a finished turn
  awaiting keep/discard (a "Clean" merge phase). A chat with nothing to review
  should not open on Changes.

  Scenario: a fresh chat with nothing to review opens on View
    Given the workbench is open
    When I start a new chat in Personal
    Then the content viewer is on the "view" tab

  Scenario: after a turn finishes, the Changes review surface leads
    Given the workbench is open
    When I start a new chat in Personal
    And I request review for the next change
    And I task the agent with "make a small change"
    Then the content viewer is on the "diff" tab
