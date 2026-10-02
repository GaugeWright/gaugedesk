@ui-mocked
Feature: A workbench action that fails says why (error path)

  The workbench records each action's outcome in a status that is not on
  screen, so a failure written only there reads as a control that did nothing.
  An action that fails must say why where it was taken, until it is dismissed,
  and must not lose what the reader was sending; routine success is not shown.

  Scenario: a refused chat start keeps the message and says why
    Given the workbench is open
    When starting a chat is refused with "the selected account has no admission to this local Home"
    And I task the agent with "draft a welcome note" from the empty chat
    Then the composer says "couldn't start a chat — the selected account has no admission to this local Home"
    And the message "draft a welcome note" is back in the composer

  Scenario: a file dropped with no chat open says why in Files
    Given the workbench is open
    Then the files pane shows no action error
    When I drop the file "notes.txt" containing "context" on Files
    Then the files pane shows the action error "Open a chat before importing files."
    When I dismiss the files pane's action error
    Then the files pane shows no action error
