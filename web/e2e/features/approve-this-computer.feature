@ui-mocked
Feature: Approve this computer from one that holds the account's keys (DR-0359, DR-0361)

  An account keeps one set of keys across its computers. A computer signed in
  to an account whose keys another computer holds cannot make itself
  reachable for that account until it is approved from there, or the
  account's recovery code restores the keys here.

  Whether this computer needs approval, the enrollment it joins and the
  recovery routes are answered by the window's own control plane, which this
  browser lane does not reach; they are simulated here and proven against the
  real plane by crates/app/src/account_publish_tests.rs,
  crates/app/src/device_enroll_drive.rs and crates/app/src/account_recovery.rs.

  Scenario: a computer that needs approval joins with a matching code
    Given another computer holds the keys of "dana@example.com"
    And the workbench is open
    Then the account bar offers "Approve this computer"
    When I choose to approve this computer
    Then the approval names "dana@example.com"
    When I paste the other computer's ticket and join
    Then this computer shows the matching code "482913"
    And the approval finishes

  Scenario: a computer that needs approval restores the keys from the recovery code
    Given another computer holds the keys of "dana@example.com"
    And the workbench is open
    When I choose to approve this computer
    And I restore with the recovery code "AAAA-BBBB-CCCC"
    Then the recovery code "AAAA-BBBB-CCCC" was sent
    And the approval finishes

  Scenario: the account menu shows the recovery code
    Given this computer holds the keys of "dana@example.com" with the recovery code "1A2B-3C4D-5E6F"
    And the workbench is open
    When I open the account menu
    And I choose "Recovery code" in the account menu
    Then the recovery code "1A2B-3C4D-5E6F" is shown
