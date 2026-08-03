@transport
Feature: Engagements

  As a user I can open a new engagement — a *work* chat rooted on a placement (an
  archetype installed on a project, ADR 0035) in an isolated worktree — so I can
  start work without touching main.

  Scenario: open a new engagement
    Given a new engagement
    Then the run phase is "Init"
