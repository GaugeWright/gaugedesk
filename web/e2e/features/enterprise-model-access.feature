@transport @enterprise-composition
Feature: Enterprise Provider Connections reaches local Model access

  Inside GaugeDesk, Provider Connections opens the person's local Model access
  (DR-0360). These journeys use the ordinary enterprise composition and its
  existing desktop-session fixture, then retain actual local writes across a
  reload. They do not verify a provider key or a managed billing service.

  Scenario: enterprise Provider Connections opens local Model access and retains a linked provider
    Given the workbench is open
    And I am signed in to my GaugeWright account on this desktop
    When I open local Model access from enterprise Provider Connections
    And I link a local enterprise OpenAI credential
    Then the local enterprise provider link survives reload through Provider Connections
    And no request to the control plane failed

  Scenario: enterprise Provider Connections opens local Model access and retains managed inference settings
    Given the workbench is open
    And I am signed in to my GaugeWright account on this desktop
    When I open local Model access from enterprise Provider Connections
    And I save local enterprise managed inference settings
    Then the local enterprise managed inference settings survive reload through Provider Connections
    And no request to the control plane failed
