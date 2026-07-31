import { createEffect, createResource, createSignal, Show, type JSX } from "solid-js";
import { App } from "@gaugewright/workbench-web";
import {
    EnterpriseControlPlane,
    type AdminCapabilityDiscovery,
} from "@gaugewright/enterprise-client";
import { AdminEnvironment } from "./AdminEnvironment";

type WorkbenchMode = "work" | "admin";

export function requestedWorkbenchMode(search: string): WorkbenchMode {
    return new URLSearchParams(search).get("environment") === "admin" ? "admin" : "work";
}

function writeWorkbenchMode(mode: WorkbenchMode): void {
    const url = new URL(window.location.href);
    if (mode === "admin") url.searchParams.set("environment", "admin");
    else url.searchParams.delete("environment");
    window.history.replaceState(window.history.state, "", `${url.pathname}${url.search}${url.hash}`);
}

/** One enterprise GaugeDesk composition. Work stays mounted throughout; the
 *  Administration Environment mounts only after the Home admits at least one
 *  capability, then stays mounted so moving between Environments loses no state. */
export function EnterpriseWorkbench(): JSX.Element {
    const initialMode = requestedWorkbenchMode(window.location.search);
    const [requestedMode, setRequestedMode] = createSignal<WorkbenchMode>(initialMode);
    const [adminMounted, setAdminMounted] = createSignal(false);
    const [tenant, setTenant] = createSignal<string | null>(null);
    const api = new EnterpriseControlPlane(undefined, { tenant });
    const [discovery] = createResource(async (): Promise<AdminCapabilityDiscovery> => {
        try {
            return await api.adminCapabilities();
        } catch {
            return {
                capabilities: [],
                agent: { message_attachments: false, additional_tools: false, tools: [] },
            };
        }
    });
    const adminAvailable = () => (discovery()?.capabilities.length ?? 0) > 0;
    const adminVisible = () => requestedMode() === "admin" && adminAvailable();

    const selectMode = (mode: WorkbenchMode) => {
        if (mode === "admin") {
            if (!adminAvailable()) return;
            setAdminMounted(true);
        }
        setRequestedMode(mode);
        writeWorkbenchMode(mode);
    };

    createEffect(() => {
        if (discovery.loading) return;
        if (requestedMode() === "admin" && adminAvailable()) {
            setAdminMounted(true);
        } else if (requestedMode() === "admin") {
            // A deep link is only a navigation request. Remove it when the Home
            // does not admit this actor into any Administration capability.
            selectMode("work");
        }
    });

    return (
        <>
            <div hidden={adminVisible()} data-work-environment>
                <App
                    onTenantContextChange={setTenant}
                    environmentAction={{
                        label: "Administration",
                        available: adminAvailable,
                        open: () => selectMode("admin"),
                    }}
                />
            </div>
            <Show when={adminMounted()}>
                <div hidden={!adminVisible()} data-admin-environment>
                    <AdminEnvironment api={api} onReturnToWork={() => selectMode("work")} />
                </div>
            </Show>
        </>
    );
}
