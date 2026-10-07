@ui-mocked
Feature: Move signed-out projects to the signed-in account (DR-0328 §7)

  Work done on a desktop without signing in belongs to the computer's local
  account. It reaches a signed-in account only by an explicit transfer, so the
  window names the account and every project before anything moves, and moves
  only the projects the person leaves ticked.

  The window's control plane answers which projects could move only to the
  window itself with an account session, which this browser lane is not; the
  two routes are simulated here and proven against the real plane by
  crates/app/src/project_transfer_tests.rs.

  Scenario: the account menu moves the chosen signed-out projects to the signed-in account
    Given this computer has signed-out projects "Garden plans" and "Tax notes" for "dana@example.com"
    And the workbench is open
    When I open the account menu
    And I choose "Move signed-out projects to dana@example.com" in the account menu
    Then the transfer names "dana@example.com" and the projects "Garden plans" and "Tax notes"
    And the transfer offers "Move 2 projects to dana@example.com"
    When I untick "Tax notes"
    Then the transfer offers "Move 1 project to dana@example.com"
    When I confirm the transfer
    Then the transfer posted only "Garden plans"
    And the account menu offers to move only "Tax notes"
