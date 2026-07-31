Feature: Round 6 — plain-language history, a keep guard, and consistent archetype wording

  The round-6 review found the "history" overlay dumped the raw event-sourcing
  log and a state-machine debug panel; the top-bar keep merged unreviewed work in
  one click with no undo; the internal config file headlined every review diff;
  and the chat header never showed the chat's own name. These scenarios lock in
  the fixes.

  Scenario: the history Activity list is plain language, with no raw event JSON or state-machine buttons
    Given a new engagement
    When I task the agent with "draft a thank-you email"
    Then the run phase is "Completed"
    When I open the audit shelf
    Then the history shows the plain activity for my request "draft a thank-you email"
    And the history shows no raw engine event names
    And the history shows no review state-machine controls

  Scenario: the raw event log is still reachable behind a developer toggle
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I open the audit shelf
    And I reveal the raw event log
    Then the audit timeline shows "RunCompleted"

  Scenario: keeping work from the task bar requires a confirming second click
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the task bar shows a review
    When I click keep on the task bar review
    Then the task bar keep is armed for confirmation
    And the review is still pending in the task bar
    When I click keep on the task bar review
    Then the review is cleared from the task bar

  Scenario: runtime settings never enter the target review
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the changed-files review hides the internal settings file
    And the review offers no internal-file toggle

  Scenario: the chat header shows the chat's own name
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the chat header shows the title "draft a tagline for spring"

  Scenario: renaming a chat updates the open chat header live (event-driven)
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the chat header shows the title "draft a tagline for spring"
    When I rename the open chat to "Spring campaign"
    Then the chat header shows the title "Spring campaign"
