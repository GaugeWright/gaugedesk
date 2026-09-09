@transport
Feature: A whip program's Structure and Instances views

  A `.whip` file is a program with runtime state, so the content viewer offers
  two views the other files have no meaning for. Every project already runs one
  — the inbound gate — so this is the shape a person meets without opting in.

  The Instances view earns its place on one line: a static effect a firing
  **never requested** has no row anywhere in the runtime, so the event log cannot
  tell it apart from an effect that does not exist in the program. Only the
  compiled structure knows it was there to not happen.

  Scenario: a whip program offers Structure and Instances; an ordinary file does not
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "gates/inbound.whip" in the workspace
    Then the content viewer offers the "structure" tab
    And the content viewer offers the "instances" tab
    When I select the file "agent-note.txt" in the workspace
    Then the content viewer does not offer the "structure" tab
    And the content viewer does not offer the "instances" tab

  Scenario: Structure draws the rules and the facts that couple them
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "gates/inbound.whip" in the workspace
    And I open the "structure" tab
    Then the structure view names the rule "implement_ready_ticket"
    And the rule graph couples "table_workspaces" to "implement_ready_ticket" by "schema:WorkspaceReady"
    # The coupling a resource read makes, which the compiler's own rule graph
    # could not see until DR-0085 taught it to carry a resource edge.
    And the rule graph couples "file_ticket" to "implement_ready_ticket" by "tracker:backlog"
    # And the one that makes the workflow go round: a rule matching a fact it
    # writes itself. DR-0081 admits the cycle when it is paced, so this is a
    # shape to draw, not an error to report.
    And the rule graph shows "implement_ready_ticket" feeding itself

  Scenario: Instances is honest about a program nothing has run
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "gates/inbound.whip" in the workspace
    And I open the "instances" tab
    # The gate has screened nothing in a fresh project, so there is no instance
    # to draw. The view says so rather than drawing a fixture: the marks in this
    # tab are read from runtime stores, and an empty store is an empty tab. The
    # never-requested distinction that is this view's reason to exist is covered
    # against a real projection in `whip-view.test.ts`, where a run can be
    # constructed; driving the gate through the browser is not something this
    # suite can do yet.
    Then the instances view says nothing is running
