# pair-two-machines-and-collaborate-both-ways
@transport
Feature: Cross-machine federation

  Two authorities on two control planes pair over the network and collaborate
  through the cert-pinned relay legs, driven from the workbench UI. Alice is the
  primary instance (port 7878); Bob is the peer (port 7879), each exposing the
  distinct authority derived from its governance root, reached by pointing a
  second browser window at it with ?cp=.

  # One scenario, one pairing: the rendezvous broker is shared and long-lived, so
  # a single pairing keeps its parked receiver legs unambiguous (re-pairing across
  # scenarios would leave stale legs on the reused session tokens).
  Scenario: pair two machines and collaborate both ways
    Given the two federated workbenches are open
    When the two authorities pair with each other
    When the owner offers projects for manual handoff consent
    Then the target accepts, declines, and batch-accepts through the shipped UI
    When the owner offers and cancels another handoff through the shipped UI
    Then the source stays home and the target cannot accept the cancelled offer
    When the owner hands off a project's home
    Then the project's handoff is committed to the target
    When the owner creates a combined invite for another project
    And the target accepts the combined invite
    Then the target manages the invited project's data and operator grant
    When the operator places a co-drive run
    Then the target exercises once, standing, and denied run admission
    # mobile-controller-rejection-production-client-lifecycle
    When a phone proves a controller request
    Then the holder rejects the phone through the shipped Devices UI
    When the holder enrolls the target as another account device
    Then both shipped clients complete the same-code authorization
    When the owner disconnects the peer through the shipped Devices UI
    Then the revoked peer is retained for audit and future work is refused
