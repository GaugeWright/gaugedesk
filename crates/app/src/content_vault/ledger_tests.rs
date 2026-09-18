use super::*;
use std::io::{BufReader, Read};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

// Exercise the real blocking HTTP adapter, including method, route and body.
fn server(responses: Vec<(u16, String)>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    listener.set_nonblocking(true).unwrap();
    let worker = thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, response) in responses {
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "ledger request did not arrive");
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("ledger fixture accept: {error}"),
                }
            };
            // On macOS an accepted socket inherits the listener's non-blocking
            // flag (Linux clears it), so the first read below raced the client's
            // bytes and failed with EAGAIN whenever the machine was busy enough
            // for accept to win. The reads want the timeout, not the flag.
            // Clearing the flag turns a spurious `EAGAIN` into a wait, which is
            // the point — but a wait with no deadline is the other way this
            // hangs. The read is bounded below; the response write was not, and
            // the fixture thread is joined without a deadline of its own, so a
            // client that connected and never drained would park it forever.
            // Responses here are a few hundred bytes, so this is theoretical
            // today; it is one line to keep it that way.
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let mut length = 0;
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).unwrap() > 0);
                if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                    length = value.trim().parse::<usize>().unwrap();
                }
                request.push_str(&line);
                if line == "\r\n" {
                    break;
                }
            }
            let mut body = vec![0; length];
            reader.read_exact(&mut body).unwrap();
            request.push_str(&String::from_utf8(body).unwrap());
            requests.push(request);
            write!(
                stream,
                "HTTP/1.1 {status} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                response.len()
            ).unwrap();
        }
        requests
    });
    (origin, worker)
}

fn ids(values: &[String]) -> String {
    serde_json::json!({ "key_ids": values }).to_string()
}

#[test]
fn confirmed_local_records_reopen_and_reject_malformed_or_incomplete_history() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("erased.ledger");
    let ledger = LocalFileErasureLedger::new(&path);
    assert!(ledger.recorded_confirmed().unwrap().is_empty());
    assert!(ledger.record_confirmed("not-an-id").is_err());
    assert!(!path.exists());
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    for id in [&b, &a, &b] {
        ledger.record_confirmed(id).unwrap();
    }
    assert_eq!(
        LocalFileErasureLedger::new(&path)
            .recorded_confirmed()
            .unwrap(),
        vec![a.clone(), b]
    );
    for malformed in [
        a.clone(),
        format!("{a}\ninvalid\n"),
        format!("{a}\n\n"),
        format!(" {a}\n"),
        format!("{}\n", "A".repeat(64)),
    ] {
        std::fs::write(&path, malformed).unwrap();
        assert_eq!(
            ledger.recorded_confirmed().unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
    }
    std::fs::write(&path, [255]).unwrap();
    assert!(ledger.recorded_confirmed().is_err());
}

#[test]
fn confirmed_local_append_waits_for_another_instances_reader() {
    use std::sync::mpsc;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("erased.ledger");
    let a = "a".repeat(64);
    LocalFileErasureLedger::new(&path)
        .record_confirmed(&a)
        .unwrap();
    let reader = std::fs::File::open(&path).unwrap();
    reader.lock_shared().unwrap();
    let writer_path = path.clone();
    let (started_tx, started_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();
    let worker = thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = LocalFileErasureLedger::new(writer_path).record_confirmed(&"b".repeat(64));
        finished_tx.send(result).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(matches!(
        finished_rx.recv_timeout(Duration::from_millis(50)),
        Err(mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(std::fs::read_to_string(&path).unwrap(), format!("{a}\n"));
    reader.unlock().unwrap();
    finished_rx
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    worker.join().unwrap();
    assert_eq!(
        LocalFileErasureLedger::new(path)
            .recorded_confirmed()
            .unwrap(),
        vec![a, "b".repeat(64)]
    );
}

#[test]
fn confirmed_remote_record_requires_acknowledgement_and_matching_readback() {
    let key = "a".repeat(64);
    for (responses, success) in [
        (vec![(503, "{}".into())], false),
        (vec![(202, "{}".into()), (200, ids(&[]))], false),
        (
            vec![(200, "{}".into()), (200, ids(&["b".repeat(64)]))],
            false,
        ),
        (vec![(200, "{}".into()), (503, "{}".into())], false),
        (
            vec![(200, "{}".into()), (200, ids(std::slice::from_ref(&key)))],
            true,
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("erased.ledger");
        let (origin, worker) = server(responses);
        let ledger = EdgeErasureLedger::new(
            &origin,
            "fixture-token".into(),
            LocalFileErasureLedger::new(&path),
        );
        assert_eq!(ledger.record_confirmed(&key).is_ok(), success);
        // Failure preserves the local tombstone for refusal/retry; it does not
        // turn an unconfirmed remote write into a successful erasure receipt.
        assert_eq!(
            LocalFileErasureLedger::new(path)
                .recorded_confirmed()
                .unwrap(),
            vec![key.clone()]
        );
        let requests = worker.join().unwrap();
        assert!(requests[0].starts_with("POST /internal/erasure-ledger HTTP/1.1\r\n"));
        assert!(requests[0]
            .to_ascii_lowercase()
            .contains("authorization: bearer fixture-token\r\n"));
        assert!(requests[0].ends_with(&serde_json::json!({ "key_id": key }).to_string()));
        for request in &requests[1..] {
            assert!(request.starts_with("GET /internal/erasure-ledger HTTP/1.1\r\n"));
        }
    }
}

#[test]
fn confirmed_remote_read_refuses_outage_and_malformed_entries_despite_local_history() {
    for (status, response) in [
        (503, "{}".into()),
        (200, "not json".into()),
        (200, "{}".into()),
        (200, "{\"key_ids\":[42]}".into()),
        (200, "{\"key_ids\":[\"short\"]}".into()),
        (200, ids(&["A".repeat(64)])),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalFileErasureLedger::new(dir.path().join("erased.ledger"));
        local.record_confirmed(&"a".repeat(64)).unwrap();
        let (origin, worker) = server(vec![(status, response)]);
        let ledger = EdgeErasureLedger::new(&origin, "fixture-token".into(), local);
        assert!(ledger.recorded_confirmed().is_err());
        assert_eq!(worker.join().unwrap().len(), 1);
    }
    let dir = tempfile::tempdir().unwrap();
    let ledger = EdgeErasureLedger::new(
        "http://127.0.0.1:1",
        "fixture-token".into(),
        LocalFileErasureLedger::new(dir.path().join("erased.ledger")),
    );
    assert!(ledger.recorded_confirmed().is_err());
    assert!(ledger.record_confirmed(&"a".repeat(64)).is_err());
}

#[test]
fn confirmed_remote_read_unions_both_authorities_without_queuing_writes() {
    let dir = tempfile::tempdir().unwrap();
    let local = LocalFileErasureLedger::new(dir.path().join("erased.ledger"));
    let a = "a".repeat(64);
    let b = "b".repeat(64);
    local.record_confirmed(&b).unwrap();
    let (origin, worker) = server(vec![(200, ids(&[a.clone(), a.clone()]))]);
    let ledger = EdgeErasureLedger::new(&origin, "fixture-token".into(), local);
    assert_eq!(ledger.recorded_confirmed().unwrap(), vec![a, b]);
    let requests = worker.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /internal/erasure-ledger HTTP/1.1\r\n"));
}

#[test]
fn incomplete_remote_configuration_never_confirms_local_recovery_as_authority() {
    for (origin, token, hosted) in [
        (None, None, true),
        (Some("https://example.invalid".into()), None, false),
        (None, Some("fixture-token".into()), false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let ledger = erasure_ledger_from_config(dir.path(), origin, token, hosted);
        assert!(ledger.recorded_confirmed().is_err());
        let id = "a".repeat(64);
        assert!(ledger.record_confirmed(&id).is_err());
        // Recovery retains locally pending erasure without claiming confirmation.
        assert_eq!(ledger.recorded().unwrap(), vec![id]);
        let vault = ContentVault::new(
            dir.path().join("content-keys"),
            Box::new(crate::at_rest::LoopbackKeyWrap::new([7; 32])),
        )
        .with_ledger(ledger);
        assert!(vault.initialize_scope_key("project").is_err());
        assert!(!vault.key_path("project").exists());
    }
    let dir = tempfile::tempdir().unwrap();
    assert!(erasure_ledger_from_config(dir.path(), None, None, false)
        .recorded_confirmed()
        .unwrap()
        .is_empty());
    let (origin, worker) = server(vec![(200, ids(&[]))]);
    assert!(erasure_ledger_from_config(
        dir.path(),
        Some(origin),
        Some("fixture-token".into()),
        true
    )
    .recorded_confirmed()
    .unwrap()
    .is_empty());
    assert_eq!(worker.join().unwrap().len(), 1);
}
