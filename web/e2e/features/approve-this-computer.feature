@ui-mocked
Feature: Restore account keys to this computer after sign-in (DR-0478)

  A fresh account sign-in normally restores the keys from private Hub custody.
  If an older account has not deposited its keys yet, the computer offers
  another sign-in after a key-holding computer updates. The recovery code is
  the emergency path when neither Hub custody nor another computer is available.

  The window's control plane answers reach and recovery, which this mocked
  browser lane simulates. Rust tests cover key custody, root matching, and
  encrypted delivery to the receiving device key.

  Scenario: an older computer awaiting a key copy offers account sign-in
    Given another computer holds the keys of "dana@example.com"
    And the workbench is open
    Then the account bar offers "Connect this computer"
    When I open the computer connection dialog
    Then the connection names "dana@example.com"
    When I choose to sign in again
    Then account sign-in is shown

  Scenario: a computer with no available key copy uses emergency recovery
    Given another computer holds the keys of "dana@example.com"
    And the workbench is open
    When I open the computer connection dialog
    And I restore with the recovery code "AAAA-BBBB-CCCC"
    Then the recovery code "AAAA-BBBB-CCCC" was sent
    And the approval finishes

  Scenario: the account menu shows the recovery code
    Given this computer holds the keys of "dana@example.com" with the recovery code "1A2B-3C4D-5E6F"
    And the workbench is open
    When I open the account menu
    And I choose "Recovery code" in the account menu
    Then the recovery code "1A2B-3C4D-5E6F" is shown
