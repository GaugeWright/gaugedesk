@transport
Feature: One chat spans several work targets

  Scenario: target selection is explicit and remains visible
    Given a project with two eligible work targets
    When I start a chat in that multi-target project
    Then the target picker requires an explicit selection
    When I select every target and start the chat
    Then the chat shows both selected targets
    And Files shows two target partitions

  Scenario: a target revision changes later write authority
    Given a project with two eligible work targets
    When I start a chat in that multi-target project
    And I select every target and start the chat
    And I change the Reference target to read-only
    Then the Reference target is visibly read-only
    And a direct save to the read-only target is refused

  Scenario: desktop quick start also requires explicit targets
    Given Personal has two eligible work targets
    When I submit the empty-state composer
    Then quick start asks for an explicit target set

  Scenario: one project workstream groups chats across placements and settles separately
    Given a project with two eligible work targets
    And two placements have chats in one project workstream
    Then the project workstream groups both chats
    When I promote collaboration and start a later target settlement
    Then promotion and settlement are projected separately with recovery actions

  Scenario: a historical fork retries into an explicit current home
    Given a chat has a fork point on a workstream that is later archived
    When I fork at that point without choosing a replacement home
    Then the archived home is refused and an explicit Main retry succeeds
