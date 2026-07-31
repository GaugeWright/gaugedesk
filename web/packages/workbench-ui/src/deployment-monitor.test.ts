import { describe, expect, it, vi } from "vitest";
import {
    deploymentMonitorIntervalMs,
    startDeploymentMonitor,
    type DeploymentMonitorScheduler,
} from "./deployment-monitor";

function controlledScheduler(): {
    scheduler: DeploymentMonitorScheduler;
    tick: () => void;
    clear: ReturnType<typeof vi.fn>;
} {
    let tick = () => {};
    const clear = vi.fn();
    return {
        scheduler: {
            setInterval(handler, timeoutMs) {
                expect(timeoutMs).toBe(deploymentMonitorIntervalMs);
                tick = handler;
                return 7;
            },
            clearInterval(handle) {
                expect(handle).toBe(7);
                clear();
            },
        },
        tick: () => tick(),
        clear,
    };
}

describe("deployment monitor", () => {
    it("publishes bounded inspection updates and stops cleanly", async () => {
        const clock = controlledScheduler();
        const observed = vi.fn();
        const failed = vi.fn();
        const stop = startDeploymentMonitor(
            async () => ({ sessions: 2 }),
            observed,
            failed,
            clock.scheduler,
            () => 42,
        );

        clock.tick();
        await vi.waitFor(() =>
            expect(observed).toHaveBeenCalledWith({ sessions: 2 }, 42)
        );
        expect(failed).not.toHaveBeenCalled();

        stop();
        expect(clock.clear).toHaveBeenCalledOnce();
        clock.tick();
        await Promise.resolve();
        expect(observed).toHaveBeenCalledOnce();
    });

    it("never overlaps inspections and recovers after an error", async () => {
        const clock = controlledScheduler();
        let release: ((value: string) => void) | undefined;
        const inspect = vi.fn(() =>
            new Promise<string>((resolve) => {
                release = resolve;
            })
        );
        const observed = vi.fn();
        const failed = vi.fn();
        startDeploymentMonitor(
            inspect,
            observed,
            failed,
            clock.scheduler,
        );

        clock.tick();
        clock.tick();
        expect(inspect).toHaveBeenCalledOnce();
        release?.("fresh");
        await vi.waitFor(() =>
            expect(observed).toHaveBeenCalledWith("fresh", expect.any(Number))
        );

        inspect.mockRejectedValueOnce(new Error("offline"));
        clock.tick();
        await vi.waitFor(() => expect(failed).toHaveBeenCalledOnce());
        clock.tick();
        expect(inspect).toHaveBeenCalledTimes(3);
    });
});
