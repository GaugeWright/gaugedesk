@transport
Feature: The human task queue (top bar)

  As a user, work that needs me surfaces in the top bar as a task queue —
  current-first — so I can act on it without hunting for it (navigation.md B1).
  The `review` ask is gone with the per-change hold (ADR 0136); what remains here
  is assignment. `answer` and `repair` are covered in round6/queue.

  # roster-assignment-production-client
  @transport
  Scenario: a desktop owner assigns tracker work through the active roster
    Given an assignable onboarding task
    When I assign the onboarding task to the active owner
    Then the onboarding task shows the active owner
