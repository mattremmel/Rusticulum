//! Smoke test for the `reticulum-node` binary.

#[cfg(unix)]
#[test]
fn binary_starts_and_stops_cleanly() {
    use std::io::{BufRead, BufReader};
    use std::process::{Command, Stdio};

    let bin = env!("CARGO_BIN_EXE_reticulum-node");

    // Write a minimal config to a temp file
    let config_content = b"[node]\nenable_storage = false\nshare_instance = false\n";
    let mut config_file = tempfile::NamedTempFile::new().unwrap();
    std::io::Write::write_all(&mut config_file, config_content).unwrap();

    // Redirect stdout to a temp file (tracing_subscriber writes to stdout by default)
    let stdout_file = tempfile::NamedTempFile::new().unwrap();
    let stdout_writer = stdout_file.reopen().unwrap();

    let child = Command::new(bin)
        .args(["--config", config_file.path().to_str().unwrap()])
        .env("RUST_LOG_FORMAT", "json")
        .env("RUST_LOG", "info")
        .stdout(Stdio::from(stdout_writer))
        .stderr(Stdio::null())
        .spawn()
        .expect("failed to spawn reticulum-node");

    let pid = child.id();

    // Give it time to start up and produce log output
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Send SIGINT
    Command::new("kill")
        .args(["-INT", &pid.to_string()])
        .status()
        .expect("failed to send SIGINT");

    // Wait with a safety timeout — spawn a thread that kills after 5s
    let pid_for_guard = pid;
    let guard = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let _ = Command::new("kill")
            .args(["-9", &pid_for_guard.to_string()])
            .status();
    });

    let output = child.wait_with_output().expect("failed to wait on child");

    // Guard thread will exit on its own
    drop(guard);

    assert!(
        output.status.success(),
        "expected exit code 0, got {:?}",
        output.status.code()
    );

    // Read stdout from the temp file
    let stdout_content = std::fs::read_to_string(stdout_file.path()).unwrap();

    // Verify stdout contains at least one JSON log line
    let reader = BufReader::new(stdout_content.as_bytes());
    let has_json_line = reader
        .lines()
        .any(|line| line.is_ok_and(|l| l.starts_with('{')));
    assert!(
        has_json_line,
        "expected at least one JSON log line, got: {stdout_content}"
    );
}
