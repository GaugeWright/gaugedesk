Feature: Content search reaches into the chat log and worktree files (SEARCH-1/2)

  Search matches not only chat titles but the chat's content: its transcript (the
  chat-log tier, SEARCH-1) and its worktree files (the file-content tier, SEARCH-2).
  A chat whose log or files mention the query surfaces in the tree even when its title
  does not, carrying a snippet of the match (navigation.md "Search scope and
  relevance"). The title tier stays a client-side filter; the log and file tiers are
  the server's GET /search (log ranks above file).

  Scenario: a word only in the chat log surfaces the chat with a snippet
    Given the workbench is open
    When I start a new chat in Personal
    And I task the agent with "review the quarterly numbers"
    And I search the facets for "agent-note"
    Then a chat surfaces with a content snippet

  # The fake agent writes "agent-note for task: <task>" into agent-note.txt in the
  # chat's worktree. The phrase "for task" appears only in that file, never in the
  # transcript or any title — so a hit on it exercises the SEARCH-2 file tier.
  Scenario: a word only in a worktree file surfaces the chat with a snippet
    Given the workbench is open
    When I start a new chat in Personal
    And I task the agent with "review the quarterly numbers"
    And I search the facets for "for task"
    Then a chat surfaces with a content snippet
