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
