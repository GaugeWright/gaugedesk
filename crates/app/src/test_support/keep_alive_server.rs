//! A plain HTTP/1.1 server on loopback that keeps each connection open and
//! answers every request on it with the same JSON body, counting connections
//! and requests apart, so a test can tell a reused connection from a new one.
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

pub(crate) struct KeepAliveServer {
    pub url: String,
    connections: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
}

impl KeepAliveServer {
    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

pub(crate) fn keep_alive_server(body: &'static str) -> KeepAliveServer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let (accepted, answered) = (connections.clone(), requests.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(stream) = stream else { return };
            accepted.fetch_add(1, Ordering::SeqCst);
            let answered = answered.clone();
            std::thread::spawn(move || serve(stream, body, &answered));
        }
    });
    KeepAliveServer {
        url,
        connections,
        requests,
    }
}

/// Requests carry no body here, so a request ends at its blank line.
fn serve(stream: TcpStream, body: &str, answered: &AtomicUsize) {
    let Ok(read_half) = stream.try_clone() else {
        return;
    };
    let mut reader = BufReader::new(read_half);
    let mut writer = stream;
    loop {
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => return,
                Ok(_) if line == "\r\n" => break,
                Ok(_) => {}
            }
        }
        answered.fetch_add(1, Ordering::SeqCst);
        let response = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n{body}",
            body.len()
        );
        if writer.write_all(response.as_bytes()).is_err() {
            return;
        }
    }
}
