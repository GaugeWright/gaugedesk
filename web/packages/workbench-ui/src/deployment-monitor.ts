export const deploymentMonitorIntervalMs = 10_000;

export interface DeploymentMonitorScheduler {
    setInterval(handler: () => void, timeoutMs: number): number;
    clearInterval(handle: number): void;
}

export function startDeploymentMonitor<T>(
    inspect: () => Promise<T>,
    observed: (value: T, at: number) => void,
    failed: (reason: unknown) => void,
    scheduler: DeploymentMonitorScheduler,
    now: () => number = Date.now,
): () => void {
    let inFlight = false;
    let stopped = false;
    const tick = async () => {
        if (inFlight || stopped) return;
        inFlight = true;
        try {
            const value = await inspect();
            if (!stopped) observed(value, now());
        } catch (reason) {
            if (!stopped) failed(reason);
        } finally {
            inFlight = false;
        }
    };
    const handle = scheduler.setInterval(
        () => void tick(),
        deploymentMonitorIntervalMs,
    );
    return () => {
        stopped = true;
        scheduler.clearInterval(handle);
    };
}
