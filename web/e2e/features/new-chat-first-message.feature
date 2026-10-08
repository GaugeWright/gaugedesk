@ui-mocked @core
Feature: A new chat takes its first message at once (error path)

  A chat is selected the moment it exists, before the workspace projection
  says which project it is in, and a turn captures the project its work is
  routed by when it starts. A first message sent in that moment must run in
  the chat's own project, not be refused because the route moved under it as
  "Task project selection changed" (WS-892). The Home is made slow to answer,
  as the production canary Home is under load, so the moment is long enough
  to send in.

  Scenario: a message sent straight after starting a chat in a project runs there
    Given the workbench is open
    When I create a project named "Launch plan"
    And the Home is slow to answer workspace and actor reads
    And I start a chat in project "Launch plan" and send "outline the launch" at once
    Then the turn completes
    And the composer shows no error
