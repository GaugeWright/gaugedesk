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
    And the content viewer does not offer the "view" tab
    When I select the file "agent-note.txt" in the workspace
    Then the content viewer does not offer the "structure" tab
    And the content viewer does not offer the "instances" tab

  Scenario: Structure draws the rules and the facts that couple them
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "gates/inbound.whip" in the workspace
    And I open the "structure" tab
    # The program is the project's own inbound gate, the human review gate
    # GaugeDesk seeds (crates/app/src/gate.rs, REVIEW_BY_HAND_GATE): an arrival
    # is read, a reviewer is asked through the tracker, and the verdict settles
    # it. Each step is a rule, and the fact one records is what the next one's
    # `when` picks up. Resource edges and a paced self-feeding rule are shapes
    # this gate does not have; the layout tests draw them from a sample that does.
    Then the structure view names the rule "read_item"
    And the structure view names the rule "ask_reviewer"
    And the structure view names the rule "settle"
    And the rule graph couples "read_item" to "ask_reviewer" by "schema:ItemBody"
    And the rule graph couples "ask_reviewer" to "settle" by "schema:Pending"

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
