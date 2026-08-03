@api @contract
Feature: Rename a chat
  Scenario: renaming a chat persists in the library
    Given an engagement "ren1"
    When "ren1" is renamed to "Quarterly review"
    Then the library shows a chat titled "Quarterly review"
