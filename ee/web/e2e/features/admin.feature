# authenticated-production-bundle
Feature: Admin Environment

  Administration is an enterprise Environment in the same workbench shell as the
  ordinary desktop. The enterprise workbench supplies an administrative resource
  tree and special renderings of selected secret-free canonical configuration
  documents while reusing the shared agent chat and responsive shell. Server
  capabilities remain authoritative, and Home inventory appears only after target
  admission.

  @transport @authenticated
  Scenario: Administration rejects missing identity and missing capability
    Given the authenticated enterprise tenant is reset
    Then the Administration route family enforces identity and capability

  Scenario: the Admin Environment is hidden in the solo collapse
    Given the workbench is open
    When I open the settings menu
    Then the organization admin entry is not offered

  # admin-capability-production-client-lifecycle
  @transport @authenticated
  Scenario: the Admin Environment uses the shared workbench shape
    Given the enterprise workbench is open for an administered tenant
    Then the Admin Environment shows its resource navigator, agent, dashboard, and configuration workspace

  # roster-assignment-authenticated-production-client
  @transport @authenticated
  Scenario: authenticated workbench assignment uses the active member roster
    Given the authenticated enterprise workbench has an assignable onboarding task
    When I assign the onboarding task to the active owner
    Then the onboarding task shows the active owner

  # resource-access-authenticated-production-client
  @transport @authenticated
  Scenario: an authenticated resource owner grants withheld context without identity impersonation
    Given the authenticated enterprise workbench has a withheld context source
    When I request access to the withheld context source
    And I approve access to the withheld context source
    Then the withheld context source is available

  Scenario: an admitted administrator switches between Work and Administration
    Given the enterprise workbench is open for an administered tenant
    When I return to work
    Then the ordinary Work Environment is shown
    When I open the settings menu
    Then the Administration entry is offered
    When I choose Administration
    Then the Admin Environment is shown

  @transport @authenticated
  Scenario: invite a member and see the action audited
    Given the enterprise workbench is open for an administered tenant
    When I invite member "alice@acme.com" as "admin"
    Then the member "alice@acme.com" is pending review and not yet admitted
    When I apply the pending Administration change
    Then the member "alice@acme.com" appears in the directory
    And the audit log shows the "member.invite" action

  # admin-audit-export-production-client-lifecycle
  @transport @authenticated
  Scenario: filter and export the tenant audit timeline
    Given the enterprise workbench is open for an administered tenant
    When I invite member "exported@acme.com" as "member"
    And I apply the pending Administration change
    And I filter the audit timeline to action "member.invite"
    Then every visible audit row has action "member.invite"
    When I export the filtered audit timeline as "CSV"
    Then the downloaded audit export contains "member.invite"
    When I export the filtered audit timeline as "JSON"
    Then the downloaded audit export contains "member.invite"

  @transport @authenticated
  Scenario: rejecting an Administration proposal has no domain effect
    Given the enterprise workbench is open for an administered tenant
    When I invite member "rejected@acme.com" as "member"
    Then the member "rejected@acme.com" is pending review and not yet admitted
    When I reject the pending Administration change
    Then the member "rejected@acme.com" remains absent

  @transport @authenticated
  Scenario: the Administration agent uses the same proposal and review path
    Given the enterprise workbench is open for an administered tenant
    When I ask the Administration agent to propose inviting "agent@acme.com"
    Then the Administration agent opens a reviewable member proposal for "agent@acme.com"
    When I apply the pending Administration change
    Then the member "agent@acme.com" appears in the directory

  Scenario: canonical configuration documents are secret-free records
    Given the enterprise workbench is open for an administered tenant
    Then the Admin Environment exposes canonical configuration documents

  Scenario: a special Admin file owns both its derived and raw views
    Given the enterprise workbench is open for an administered tenant
    When I open the "policy.json" configuration file
    Then its derived policy view is shown
    When I open the raw configuration editor
    Then the editor shows the canonical policy JSON

  Scenario: Admin help and agent boundaries are inspectable workspace files
    Given the enterprise workbench is open for an administered tenant
    When I open help for the selected Admin file
    Then its linked Markdown guide is shown
    And the Admin supporting files are hidden from the ordinary Files list
    When I reveal internal Admin files
    Then the Admin agent definition files are visible
    When I open the Admin agent tool manifest
    Then it contains only governance tools and no shell or web tools

  Scenario: the Admin session admits no upload capability
    Given the enterprise workbench is open for an administered tenant
    Then the Admin composer offers no attachment control
    And the Admin agent upload API is unavailable

  Scenario: software admission and reported clients are ordinary Admin files
    Given the enterprise workbench is open for an administered tenant
    When I open the "software-policy.json" configuration file
    Then its derived software admission view is shown
    When I open the "clients.json" configuration file
    Then its reported clients view is shown

  # software-policy-desktop-updater-production-client
  @transport @authenticated
  Scenario: the desktop updater reads the compatibility recovery policy
    Given the enterprise workbench is open for an administered tenant
    When I reload the administered workbench as a desktop client
    Then the shipped desktop updater reads the tenant software policy

  # placement-policy-enrolled-client-production-journey
  @transport @authenticated
  Scenario: the enrolled desktop refuses an engagement outside organization placement policy
    Given the enterprise workbench has an attested-only placement policy
    When I preview an unattested engagement in the shipped Devices UI
    Then the enrolled client reads the placement floor and refuses the engagement locally

  # admin-sso-production-client-lifecycle
  @transport @authenticated
  Scenario: the guided SSO wizard walks through the steps
    Given the enterprise workbench is open for an administered tenant
    When I launch the SSO setup wizard
    Then the SSO wizard shows the connect step
    When I advance the SSO wizard
    Then the SSO wizard shows the test step
    When I test the incomplete SSO connection
    Then the SSO test reports the incomplete configuration

  # saml-metadata-external-provider-lifecycle
  @transport @authenticated
  Scenario: an authenticated administrator advertises usable SAML metadata
    Given the enterprise workbench is open for an administered tenant
    When I launch the SSO setup wizard
    Then an identity provider can register from the advertised SAML metadata

  # scim-external-provider-lifecycle
  @transport @authenticated
  Scenario: an authenticated administrator connects a SCIM provider lifecycle
    Given the enterprise workbench is open for an administered tenant
    When I issue a SCIM credential through Administration review
    Then the external SCIM provider provisions, suspends, restores, and deletes a member

  Scenario: the Admin Environment shows the active-sessions roster
    Given the enterprise workbench is open for an administered tenant
    Then the admin console shows the active sessions roster

  Scenario: Machines use target-admitted Home projections
    Given the enterprise workbench is open for an administered tenant
    Then the Admin Environment shows the serving machine as live
    When I ask the admin agent about Machines
    Then the admin agent answers from admitted Home projections
