import type { ProjectHostsModel } from "./gaugeapp-project-host-models";

export const emptyProjectHosts: ProjectHostsModel = {
    homes: [], managed_enrollment: { available: true, reason: null, region: "test-region", capacity: { storage_bytes: 10_000_000, concurrent_agents: 2 } },
};
export const managedProjectHosts: ProjectHostsModel = {
    managed_enrollment: { ...emptyProjectHosts.managed_enrollment, available: false, reason: "Already provisioned" },
    homes: [{
        id: "cloud-home", home_id: "home:cloud:example", name: "Research host", kind: "cloud", endpoint: "https://home.example.test",
        lifecycle: "active", state: "indeterminate", repair_hint: "Connect for project inventory", projects: null,
        region: "test-region", capacity: { storage_bytes: 10_000_000, concurrent_agents: 2 }, retention_until: null,
        managed_policy: { version: 1, tenant_id: "tenant-a", isolated_workspace_enabled: false, max_attempt_nanos_usd: 1_000_000_000 },
        execution: {
            freshness: "home-admitted", queue: { total: 0 }, compute: { state: "idle", active_attempts: 0 },
            usage: { billable_nanos_usd: 0, charged_nanos_usd: 0, wall_millis: 0 },
            profiles: { durable_workflow: { available: true, reason: null }, isolated_workspace: {
                available: false, reason: "Disabled by policy", enabled_by_tenant_policy: false,
                metering: { kind: "usage", reservation_nanos_usd: 1_000_000_000, nanos_usd_per_second: 1_000_000 },
            } },
        },
    }],
};
