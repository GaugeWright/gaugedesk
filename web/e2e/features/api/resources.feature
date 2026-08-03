@api @contract
Feature: Durable context resources (M1)
  Opening a folder mints a durable, access-gated context resource; its content
  resolves through the handle only with a granted basis; tombstoning blocks future
  resolution while the handle/record survive. Driven over the control plane (HTTP).

  Scenario: opening a folder mints a granted context resource
    Given an engagement "res1"
    When a folder is opened as context in "res1"
    Then "res1" lists a granted context resource
    And its payload is not in the resource listing

  Scenario: content resolves through the handle, tombstone blocks it
    Given an engagement "res2"
    When a folder is opened as context in "res2"
    Then the context content resolves to the ingested bytes
    When the context resource is tombstoned
    Then resolving the context content is gone
    And the context resource still lists, marked tombstoned
