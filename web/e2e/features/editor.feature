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
