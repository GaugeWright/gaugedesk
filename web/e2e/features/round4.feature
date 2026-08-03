@transport
Feature: Round 4 — ownership-safe editing, legible diffs, and one canonical chat title

  GaugeDesk runtime settings are changed through Settings, while authored
  behavior is changed in the WhippleScript package draft. The split diff must
  remain legible and the TASKS bar must use one canonical chat title.

  Scenario: runtime settings stay outside the target workspace
    Given a new engagement
    When I reveal the internal files
    Then the target workspace does not contain ".agent-config.json"

  Scenario: an edit chat can save authored behavior in the package draft
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    And I select the file ".whipple/draft/persona.md" in the workspace
    And I open the "edit" tab
    And I replace the editor content with "You are a concise research assistant."
    And I save the file

  Scenario: the split diff toggle is hidden when the review panel is too narrow
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the run phase is "Completed"
    When I open the "diff" tab
    Then the split diff toggle is not offered at the default panel width

  Scenario: a finished turn surfaces in the task bar without the raw "new chat" placeholder
    Given a new engagement
    When I request review for the next change
    And I task the agent with "make a change"
    Then the task bar shows a review
    And the task bar shows no chat literally titled "new chat"
