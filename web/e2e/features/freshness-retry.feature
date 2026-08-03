@ui-mocked
Feature: Projection freshness and retry (RF-E4, error path)

  As a user, when a projection fetch fails the desktop shell must surface an
  explicit "couldn't refresh — retry" outcome instead of silently showing a stale
  view I can no longer trust. The freshness banner appears on a failed refresh and
  offers a retry that re-runs the failed loads; once the fetch succeeds again the
  banner clears.

  Scenario: a failed projection refresh shows the freshness banner and retry
    Given a new engagement
    When the projection refresh starts failing
    And I trigger a projection refresh
    Then the freshness banner is shown
    And the freshness banner offers a retry

  Scenario: retrying after the fetch recovers clears the banner
    Given a new engagement
    When the projection refresh starts failing
    And I trigger a projection refresh
    Then the freshness banner is shown
    When the projection refresh recovers
    And I retry the projection refresh
    Then the freshness banner clears
