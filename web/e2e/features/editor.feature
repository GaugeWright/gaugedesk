@transport
Feature: File editor

  Editing a worktree file in the content viewer's Edit tab and saving it commits
  the change to the engagement (git is the version history).

  Scenario: edit a worktree file and save it
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "agent-note.txt" in the workspace
    And I open the "edit" tab
    And I replace the editor content with "edited by the human"
    And I save the file
    Then the file editor shows "edited by the human"

  Scenario: a plain text file opens directly in Edit
    Given a new engagement
    When I task the agent with "make a note"
    Then the run phase is "Completed"
    When I select the file "agent-note.txt" in the workspace
    Then the content viewer is on the "edit" tab
    And the "view" tab is absent
    And the file editor shows "agent-note"

  # The Agent's authored directory is `agent/`, and `SYSTEM.md` there holds its
  # editable system-level instructions (archetype.md, DR-0247). GaugeDesk
  # derives the package under `.whipple/` from it; that is not a file to edit.
  Scenario: an edit chat can save authored behavior in the package draft
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    And I select the file "agent/SYSTEM.md" in the workspace
    Then the content viewer offers the "view" tab
    And the content viewer offers the "edit" tab
    When I open the "edit" tab
    And I replace the editor content with "You are a concise research assistant."
    And I save the file

  Scenario: the editor opens the plain text file a turn just changed
    Given a new engagement
    When I task the agent with "draft a tagline for spring"
    Then the run phase is "Completed"
    When I open the "edit" tab
    Then the file editor shows "agent-note"
