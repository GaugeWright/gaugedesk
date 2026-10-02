@transport
Feature: Audit timeline

  As a user I can inspect the ordered, append-only event log for a scope, so I
  have a durable audit trail of everything that happened.

  Scenario: the run lifecycle is recorded in order
    Given a new engagement
    When I task the agent with "do work"
    And I open the audit shelf
    Then the audit timeline shows "RunRequested"
    And the audit timeline shows "RunCompleted"

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
