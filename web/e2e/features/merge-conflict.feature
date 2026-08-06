@transport
Feature: Merge conflict repair (UX-7, INV-24)

  A definition-write that conflicts on merge must **isolate** the engagement with a
  preserved candidate + a repair context, never silently advance `main` — and the
  isolated work must be **repairable** (start over → try again → resolved). The
  conflict is staged by a test-only injection hook (`POST /test/force-conflict`,
  gated by GAUGEDESK_TEST_RESET) since a real adversarial git conflict can't be
  reproduced from the browser.

  Scenario: a conflicting merge isolates the work and is repairable
    Given a new engagement
    When merge conflict injection is on
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    When I click the tool target "agent-note.txt"
    And I open the "diff" tab
    Then the work is isolated with a repair option
    When I start the repair
    Then I can retry the merge
    When I retry the merge
    Then the merge conflict is resolved
