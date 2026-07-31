Feature: Edit vs work chats (chat rooting)

  A chat's kind is fixed at creation by what it is rooted on (ADR 0035): a chat
  created under an archetype is an *edit* chat (improve the method); a chat under
  a placement is a *work* chat. There is no mid-life toggle — the dock shows the
  kind read-only.

  Scenario: an edit chat is marked edit and the pane shows the edit kind
    Given the workbench is open
    When I create an edit chat under the archetype "Default"
    Then the chat pane kind is "edit"
    And an edit chat is marked in the nav

  Scenario: a work chat is rooted on a placement and shows the work kind
    Given a new engagement
    Then the chat pane kind is "work"
