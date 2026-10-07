import type { RouteEventClose, RouteEventStream } from "@gaugewright/control-plane-client";

/** The close reason a stream's subscriber sees when the gate lets it reconnect. */
export const EVENT_STREAMS_RESUMED: RouteEventClose = { detail: "event streams resumed" };

interface GatedStream {
    /** Stops the live connection; absent while the stream is parked. */
    stop: (() => void) | null;
    readonly open: () => void;
    readonly close: (reason?: RouteEventClose) => void;
}

/** Every event stream one control plane opens, so that an account change can
 * free the connections they hold before it sends anything (WS-581).
 *
 * A stream is a request that never ends. A desktop shell reaches every Home
 * through the co-resident control plane, so its streams all share one HTTP/1.1
 * origin, and WebKit opens at most six connections to an origin. Six streams
 * leave none for a request: a sign-out POST queued behind them never reached
 * the server, and the account menu stayed "Signing out" until a restart.
 *
 * `suspend()` stops every stream without telling its subscriber, and parks any
 * stream opened while suspended, so nothing reconnects underneath an account
 * change. `resume()`, for an account change that failed, closes each one as
 * resumed, which makes its reconnecting subscriber resolve its route again. */
export class EventStreamGate {
    private suspended = false;
    private readonly streams = new Set<GatedStream>();

    get isSuspended(): boolean {
        return this.suspended;
    }

    wrap(source: RouteEventStream): RouteEventStream {
        return (path, onMessage, onOpen, onClose) => {
            let ended = false;
            const stream: GatedStream = {
                stop: null,
                open: () => {
                    // Callbacks from a connection the gate stopped are not
                    // the subscriber's business: it was never told it closed.
                    let live = true;
                    const stop = source(
                        path,
                        (data) => { if (live && !ended) onMessage(data); },
                        () => { if (live && !ended) onOpen?.(); },
                        (reason) => {
                            if (!live || ended) return;
                            live = false;
                            ended = true;
                            this.streams.delete(stream);
                            onClose?.(reason);
                        },
                    );
                    stream.stop = () => {
                        live = false;
                        stop();
                    };
                },
                close: (reason) => {
                    if (ended) return;
                    ended = true;
                    this.streams.delete(stream);
                    onClose?.(reason);
                },
            };
            this.streams.add(stream);
            if (!this.suspended) stream.open();
            return () => {
                if (ended) return;
                ended = true;
                this.streams.delete(stream);
                stream.stop?.();
                stream.stop = null;
            };
        };
    }

    /** Stop every stream and hold new ones until `resume()`. Synchronous, so
     * the connections are released before the caller's next request. */
    suspend(): void {
        this.suspended = true;
        for (const stream of this.streams) {
            stream.stop?.();
            stream.stop = null;
        }
    }

    /** Hand every held stream back to its subscriber as closed, so each
     * resolves its route again under whatever account is now current. */
    resume(): void {
        if (!this.suspended) return;
        this.suspended = false;
        for (const stream of [...this.streams]) stream.close(EVENT_STREAMS_RESUMED);
    }
}
