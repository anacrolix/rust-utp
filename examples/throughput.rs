//! Measures loopback throughput of a single uTP connection.
//! Run with `cargo run --release --example throughput`.

use std::io::{Read, Write};
use std::time::Instant;

fn main() {
    const N: usize = 32 << 20;
    let s0 = utp::Socket::bind("127.0.0.1:0").unwrap();
    let s1 = utp::Socket::bind("127.0.0.1:0").unwrap();
    let addr = s1.local_addr();
    let reader = std::thread::spawn(move || {
        let c = s1.accept().unwrap();
        let mut got = vec![0u8; N];
        let start = Instant::now();
        (&c).read_exact(&mut got).unwrap();
        (start.elapsed(), s1)
    });
    let c = s0.connect(addr).unwrap();
    let data = vec![0xabu8; N];
    let start = Instant::now();
    (&c).write_all(&data).unwrap();
    let write_elapsed = start.elapsed();
    let (read_elapsed, _keep_alive) = reader.join().unwrap();
    let mib = (N >> 20) as f64;
    println!(
        "wrote {} MiB in {:?} ({:.1} MiB/s), reader finished in {:?}",
        N >> 20,
        write_elapsed,
        mib / write_elapsed.as_secs_f64(),
        read_elapsed,
    );
}
