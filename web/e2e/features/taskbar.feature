@transport
Feature: The human task queue (top bar)

  As a user, finished agent work that needs my review surfaces in the top bar as
  a task queue — current-first — so I can review and keep it without hunting for
  it (navigation.md B1, the human task queue).

  Scenario: a finished turn queues a review, completed from the task bar
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the task bar shows a review
    When I complete the review from the task bar
    Then the review is cleared from the task bar

  Scenario: a review task is tagged with its archetype, so the bar can colour it (#22)
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the task bar shows a review
    And the review task carries its archetype tag

  # roster-assignment-production-client
  @transport
  Scenario: a desktop owner assigns tracker work through the active roster
    Given an assignable onboarding task
    When I assign the onboarding task to the active owner
    Then the onboarding task shows the active owner
