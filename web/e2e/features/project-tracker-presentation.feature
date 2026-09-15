@ui-mocked
Feature: Project task backlog presentation (WHIP-4)

  These scenarios test the production shell against simulated tracker responses.
  Native authority and completion recovery are separately exercised through the
  actual desktop and hosted HTTP routes in project_tracker_route_tests.rs.

  Background:
    Given the workbench is open
    And a simulated project tracker backlog
    When I open the Personal project task backlog

  Scenario: the ordinary project backlog keeps unassigned and colleague work visible
    Then the backlog shows unassigned and colleague tasks
    When I open the backlog task "Make a personal assistant"
    Then the backlog shows its instructions and separate claim
    When I include completed backlog tasks
    Then the backlog shows "Earlier task"

  Scenario: a read-only recipient can inspect but cannot submit completion
    When the simulated tracker becomes read-only
    And I refresh project tasks
    And I open the backlog task "Make a personal assistant"
    Then the task completion form is unavailable

  Scenario: losing read access removes the previous task payload
    When I open the backlog task "Make a personal assistant"
    And the simulated backlog becomes unavailable
    And I refresh project tasks
    Then the backlog shows an error instead of old or empty tasks

  Scenario: a sign-in refusal gives a specific next action
    When the simulated tracker requires sign-in
    And I refresh project tasks
    Then the backlog asks me to sign in

  Scenario: uncertain completion survives refresh and reopening with the same intent
    When I open the backlog task "Make a personal assistant"
    And I submit a completion whose response is lost
    Then the backlog offers the original completion retry
    When I close and reopen the Personal task backlog
    And I include completed backlog tasks
    And I open the backlog task "Make a personal assistant"
    And I retry the pending task completion
    Then the same completion request is confirmed

  Scenario: a native failure is not presented as successful completion
    When I open the backlog task "Make a personal assistant"
    And I submit a completion that fails natively
    Then the backlog reports failed completion

  Scenario: a pending request cannot be retried from read-only access
    When I open the backlog task "Make a personal assistant"
    And I submit a completion whose response is lost
    Then the backlog offers the original completion retry
    When the simulated tracker becomes read-only
    And I refresh project tasks
    Then the original completion retry is disabled

  Scenario: a late completion response belongs to the task that was submitted
    When I open the backlog task "Make a personal assistant"
    And I submit a completion that is still in flight
    And I open the backlog task "Review the project outline"
    And the original task completion returns
    Then completion feedback does not appear on the other task
