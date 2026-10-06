@ui-mocked
Feature: A navigator action that fails says why (error path)

  A project created from the navigator can be refused, for example when the
  selected account has no admission to the Home serving this window. The
  navigator must show the refusal where the action was taken; a create that
  fails silently reads as a button that does nothing.

  Scenario: a refused project create shows its reason in the navigator
    Given the workbench is open
    When creating a project is refused with "the selected account has no admission to this local Home"
    And I create a project named "Refused project" from the navigator
    Then the navigator shows the error "the selected account has no admission to this local Home"
    When I dismiss the navigator error
    Then the navigator shows no error
