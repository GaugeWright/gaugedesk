//! One cancellable provider POST. The private runtime owns all connection tasks;
//! it is dropped before returning to the caller that owns the turn claim.
use std::io::{self, Read};
use std::time::{Duration, Instant};

pub(crate) const RESPONSE_TIMEOUT: Duration = Duration::from_secs(130);
const READ_CHECKPOINT: Duration = Duration::from_secs(2);

pub(crate) fn post<S, F, T>(
    endpoint: &str,
    headers: &[(&str, &str)],
    body: String,
    mut stopped: S,
    consume: F,
) -> Result<T, io::Error>
where
    S: FnMut() -> bool,
    F: FnOnce(u16, &mut dyn Read, &mut S) -> Result<T, io::Error>,
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .pool_max_idle_per_host(0)
        .build()
        .map_err(io::Error::other)?;
    let deadline = Instant::now() + RESPONSE_TIMEOUT;
    let mut request = client.post(endpoint).body(body);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    // The future is polled in this runtime, never spawned or retried. Dropping
    // it on Stop closes the pending request; dropping the runtime settles the
    // client's connection tasks before this function returns.
    let response = runtime.block_on(async {
        let send = request.send();
        tokio::pin!(send);
        loop {
            if stopped() {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "provider stopped",
                ));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "provider response timed out",
                ));
            }
            tokio::select! {
                result = &mut send => return result.map_err(io::Error::other),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    })?;
    let status = response.status().as_u16();
    let mut reader = ProviderReader {
        runtime: &runtime,
        response,
        pending: Vec::new(),
        offset: 0,
        deadline,
    };
    consume(status, &mut reader, &mut stopped)
}

struct ProviderReader<'a> {
    runtime: &'a tokio::runtime::Runtime,
    response: reqwest::Response,
    pending: Vec<u8>,
    offset: usize,
    deadline: Instant,
}

impl Read for ProviderReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.offset == self.pending.len() {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::other("provider response timed out"));
            }
            let chunk = self.runtime.block_on(async {
                tokio::time::timeout(READ_CHECKPOINT.min(remaining), self.response.chunk()).await
            });
            self.pending = match chunk {
                Err(_) if Instant::now() >= self.deadline => {
                    return Err(io::Error::other("provider response timed out"))
                }
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "provider read checkpoint",
                    ))
                }
                Ok(Err(error)) => return Err(io::Error::other(error)),
                Ok(Ok(None)) => return Ok(0),
                Ok(Ok(Some(bytes))) => bytes.to_vec(),
            };
            self.offset = 0;
        }
        let count = out.len().min(self.pending.len() - self.offset);
        out[..count].copy_from_slice(&self.pending[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;

    fn server(f: impl FnOnce(TcpStream) + Send + 'static) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let worker = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert_eq!(socket.read(&mut byte).unwrap(), 1);
                request.push(byte[0]);
            }
            assert!(request.starts_with(b"POST / HTTP/1.1\r\n"));
            let mut body = [0; 2];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"{}");
            f(socket);
        });
        (endpoint, worker)
    }

    #[test]
    fn delayed_headers_do_not_exhaust_stream_read_checkpoint() {
        let (endpoint, worker) = server(|mut socket| {
            thread::sleep(Duration::from_millis(2300));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
                .unwrap();
        });
        let body = post(
            &endpoint,
            &[],
            "{}".into(),
            || false,
            |status, reader, _| {
                assert_eq!(status, 200);
                let mut body = String::new();
                reader.read_to_string(&mut body)?;
                Ok(body)
            },
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(body, "{}");
    }

    #[test]
    fn stream_continues_after_a_read_checkpoint() {
        let (checkpoint, observed) = std::sync::mpsc::channel();
        let (endpoint, worker) = server(move |mut socket| {
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n")
                .unwrap();
            observed.recv_timeout(Duration::from_secs(5)).unwrap();
            socket.write_all(b"{}").unwrap();
        });
        let (body, checkpoints) = post(
            &endpoint,
            &[],
            "{}".into(),
            || false,
            |_, reader, _| {
                let mut body = Vec::new();
                let mut checkpoints = 0;
                let mut buf = [0; 8];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => return Ok((body, checkpoints)),
                        Ok(n) => body.extend_from_slice(&buf[..n]),
                        Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                            checkpoints += 1;
                            if checkpoints == 1 {
                                checkpoint.send(()).unwrap();
                            }
                        }
                        Err(error) => return Err(error),
                    }
                }
            },
        )
        .unwrap();
        worker.join().unwrap();
        assert_eq!(body, b"{}");
        assert!(checkpoints >= 1);
    }

    #[test]
    fn stop_before_headers_closes_connection_before_returning() {
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let (endpoint, worker) = server(move |mut socket| {
            stop.store(true, Ordering::SeqCst);
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "request must close on cancellation"
            );
        });
        let error = post(
            &endpoint,
            &[],
            "{}".into(),
            || stopped.load(Ordering::SeqCst),
            |_, _, _| {
                Err::<(), _>(io::Error::other(
                    "cancelled header request must not consume a response",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        worker.join().unwrap();
    }

    #[test]
    fn stopped_stalled_body_closes_connection_before_returning() {
        let (reading, read_started) = std::sync::mpsc::channel();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = stopped.clone();
        let (endpoint, worker) = server(move |mut socket| {
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n")
                .unwrap();
            read_started.recv_timeout(Duration::from_secs(5)).unwrap();
            stop.store(true, Ordering::SeqCst);
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "stalled body connection must close"
            );
        });
        let error = post(
            &endpoint,
            &[],
            "{}".into(),
            || stopped.load(Ordering::SeqCst),
            |_, reader, stopped| {
                reading.send(()).unwrap();
                let mut byte = [0];
                let result = reader.read(&mut byte);
                assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
                assert!(stopped());
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "provider stopped",
                ))
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        worker.join().unwrap();
    }

    #[test]
    fn stopped_transport_settles_before_turn_claim_is_released() {
        use crate::gaugeapp_agent::{
            claim_gaugeapp_agent_turn, gaugeapp_agent_turn_was_stopped, request_gaugeapp_agent_stop,
        };
        const THREAD: &str = "provider-transport-settlement-regression";
        let claim = claim_gaugeapp_agent_turn(THREAD).unwrap();
        let (endpoint, worker) = server(|mut socket| {
            assert!(request_gaugeapp_agent_stop(THREAD));
            assert!(
                claim_gaugeapp_agent_turn(THREAD).is_none(),
                "erasure's exclusive turn claim must remain unavailable"
            );
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let error = post(
            &endpoint,
            &[],
            "{}".into(),
            || gaugeapp_agent_turn_was_stopped(THREAD),
            |_, _, _| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        worker.join().unwrap();
        assert!(claim_gaugeapp_agent_turn(THREAD).is_none());
        drop(claim);
        assert!(claim_gaugeapp_agent_turn(THREAD).is_some());
    }

    #[test]
    fn redirect_is_returned_without_replaying_post() {
        let (endpoint, worker) = server(|mut socket| {
            socket.write_all(b"HTTP/1.1 307 Temporary Redirect\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
        });
        assert_eq!(
            post(
                &endpoint,
                &[],
                "{}".into(),
                || false,
                |status, _, _| Ok(status)
            )
            .unwrap(),
            307
        );
        worker.join().unwrap();
    }
}
