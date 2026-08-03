@transport
Feature: Per-project model access (LLM-2)

  A project may pin its own BYOK provider key in its coordination scope, overriding the
  account default for chats in that project (nearest-scope-wins at run time, ADR 0062).
  The pin is set from the project's "model access…" context-menu entry; the token is
  sealed server-side and never shown again — the surface lists provider names + a
  pinned flag only.

  Scenario: pin and unpin a provider key for a project
    Given the workbench is open
    When I create a project named "acme-co"
    And I open model access for project "acme-co"
    Then the model-access panel is open
    When I pin the provider "anthropic" for this project
    Then the project pins the provider "anthropic"
    When I unpin the provider "anthropic" for this project
    Then the project has no provider pins
