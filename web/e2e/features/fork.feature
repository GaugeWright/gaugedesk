@transport
Feature: Fork (ADR 0035/0038/0141)

  Forking gives you a copy to branch from. An archetype fork copies the method into a
  new, independent archetype; a chat fork branches the whole thread into a linked new
  chat — worktree, agent memory, and (ADR 0141) the durable transcript up to the fork
  point, inherited by lineage rather than copied.

  Scenario: forking an archetype creates an independent copy in the Library
    Given the workbench is open
    When I create an archetype named "forkable"
    Then I see the archetype "forkable"
    When I fork the archetype "forkable"
    Then I see a forked copy of the archetype "forkable"

  Scenario: forking a chat clones it into a linked new chat
    Given a new engagement
    When I switch to the "Projects" facet
    And I fork the first chat
    Then I see a forked chat

  @live-provider
  Scenario: a forked chat remembers the parent's conversation
    Given a new engagement
    When I task the agent with "Remember the number 8351. Acknowledge only, do not use tools."
    And I switch to the "Projects" facet
    And I fork the first chat
    # ADR 0141: the inherited history is visible before the fork runs anything,
    # and the seam between inherited and own lines is marked.
    Then the transcript shows "Remember the number 8351"
    And the fork point marker is visible
    When I task the agent with "What number did I ask you to remember? Reply with just the number and use no tools."
    Then the transcript shows "8351"

  Scenario: the fork tree shows a chat's lineage
    Given a new engagement
    When I switch to the "Projects" facet
    And I fork the first chat
    And I open the fork tree for the first chat
    Then the fork tree shows at least 2 chats
