# authenticated-production-bundle
@transport
Feature: Administration GaugeApp

  Administration is a tenant-scoped GaugeApp in the ordinary GaugeDesk workbench.
  It contributes server-admitted pages to the organization menu, owns a distinct
  persistent management conversation, and renders purpose-built controls in the
  content pane. Server capabilities and page models remain authoritative.

  @transport @authenticated
  Scenario: Administration rejects missing identity and missing capability
    Given the authenticated enterprise tenant is reset
    Then the Administration route family enforces identity and capability

  # admin-capability-production-client-lifecycle
  # admin-sso-production-client-lifecycle
  # admin-audit-export-production-client-lifecycle
  # placement-policy-enrolled-client-production-journey
  @transport @authenticated
  Scenario: supporting enterprise routes remain capability gated
    Given the enterprise workbench is open for an administered tenant
    Then the supporting enterprise routes expose capability, integration, audit, policy, and SSO diagnostics

  Scenario: Administration is absent without an admitted organization
    Given the authenticated enterprise tenant is reset
    When I open the enterprise workbench without identity
    Then the organization admin entry is not offered

  # gaugeapp-administration-production-client-lifecycle
  @transport @authenticated
  Scenario: Administration uses the shared workbench shape
    Given the enterprise workbench is open for an administered tenant
    Then Administration shows its menu, agent, and People workspace

  # resource-access-authenticated-production-client
  @transport @authenticated
  Scenario: an authenticated resource owner grants withheld context without identity impersonation
    Given the authenticated enterprise workbench has a withheld context source
    When I request access to the withheld context source
    And I approve access to the withheld context source
    Then the withheld context source is available

  @authenticated
  Scenario: an admitted administrator switches between Work and Administration
    Given the enterprise workbench is open for an administered tenant
    When I return to work
    Then ordinary project work is shown
    When I open the organization menu
    Then the Administration entry is offered
    When I choose Administration
    Then the Administration GaugeApp is shown

  @transport @authenticated
  Scenario: invite a member through review and receive an addressed link
    Given the enterprise workbench is open for an administered tenant
    When I invite member "alice@acme.com" as "admin"
    Then the invitation for "alice@acme.com" is pending review and not yet created
    When I apply the pending Administration change
    Then the invitation for "alice@acme.com" appears with its one-time link

  @transport @authenticated
  Scenario: rejecting an Administration proposal has no domain effect
    Given the enterprise workbench is open for an administered tenant
    When I invite member "rejected@acme.com" as "member"
    Then the invitation for "rejected@acme.com" is pending review and not yet created
    When I reject the pending Administration change
    Then the invitation for "rejected@acme.com" remains absent

  @transport @authenticated
  Scenario: the Administration agent uses the same proposal and review path
    Given the enterprise workbench is open for an administered tenant
    When I ask the Administration agent to propose inviting "agent@acme.com"
    Then the Administration agent opens a reviewable member proposal for "agent@acme.com"
    When I apply the pending Administration change
    Then the invitation for "agent@acme.com" appears with its one-time link

  @authenticated
  Scenario: the Administration conversation admits no upload capability
    Given the enterprise workbench is open for an administered tenant
    Then the Admin composer offers no attachment control
    And the Admin agent upload API is unavailable

  # software-policy-desktop-updater-production-client
  @transport @authenticated
  Scenario: the desktop updater reads the compatibility recovery policy
    Given the enterprise workbench is open for an administered tenant
    When I reload the administered workbench as a desktop client
    Then the shipped desktop updater reads the tenant software policy

  # saml-metadata-external-provider-lifecycle
  @transport @authenticated
  Scenario: Enterprise Identity advertises usable SAML metadata
    Given the enterprise workbench is open for an administered tenant
    When I open Enterprise Identity setup
    Then an identity provider can register from the advertised SAML metadata

  # scim-external-provider-lifecycle
  @transport @authenticated
  Scenario: an authenticated administrator connects a SCIM provider lifecycle
    Given the enterprise workbench is open for an administered tenant
    When I issue a SCIM credential through Administration review
    Then the external SCIM provider provisions, suspends, restores, and deletes a member

  @authenticated
  Scenario: Administration shows the active-sessions roster
    Given the enterprise workbench is open for an administered tenant
    Then the admin console shows the active sessions roster
