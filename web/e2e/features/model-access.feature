@transport
Feature: Per-project model access (LLM-2)

  A project may store its own BYOK provider key in its coordination scope, overriding the
  account default for chats in that project (nearest-scope-wins at run time, ADR 0062).
  The key is added from the Model access page in Project settings; the token is
  sealed server-side and never shown again — the surface lists provider names and
  whether each project-owned credential is present.

  Scenario: add and remove a provider key for a project
    Given the workbench is open
    When I create a project named "acme-co"
    And I open model access for project "acme-co"
    Then the model-access panel is open
    When I add the provider "anthropic" to this project
    Then the project holds the provider "anthropic"
    When I remove the provider "anthropic" from this project
    Then the project has no project-owned keys
