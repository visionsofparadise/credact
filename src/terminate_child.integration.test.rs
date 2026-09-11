use super::*;

#[cfg(unix)]
#[test]
fn escalates_to_a_forced_kill_when_the_graceful_signal_is_ignored() {
    use std::io::{BufRead, BufReader};

    use std::os::unix::process::ExitStatusExt;

    use std::process::Stdio;

    use process_wrap::std::CommandWrap;

    let mut child = CommandWrap::with_new("node", |command| {
        command
            .args([
                "-e",
                "process.on('SIGTERM', () => {}); setInterval(() => {}, 1000); process.stdout.write('ready\\n')",
            ])
            .stdout(Stdio::piped());
    })
    .spawn()
    .expect("node spawns");

    let mut ready = String::new();

    BufReader::new(child.stdout().take().expect("stdout is piped"))
        .read_line(&mut ready)
        .expect("the child reports its handler");

    assert_eq!(ready, "ready\n");

    let started_at = Instant::now();
    let status = terminate_child(child.as_mut()).expect("the child terminates");

    assert_eq!(status.signal(), Some(9));
    assert!(started_at.elapsed() < FORCED_TERMINATION);
}

#[cfg(windows)]
fn is_listed(pid: u32) -> bool {
    let output = std::process::Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .output()
        .expect("tasklist runs");

    String::from_utf8_lossy(&output.stdout).contains(&format!("\"{pid}\""))
}

#[cfg(windows)]
#[test]
fn terminates_a_windows_process_tree() {
    use std::process::Stdio;

    use std::time::{SystemTime, UNIX_EPOCH};

    use process_wrap::std::{CommandWrap, JobObject};

    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("the clock is after the epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "credact-terminate-child-{}-{unique}",
        std::process::id()
    ));

    std::fs::create_dir_all(&directory).expect("the directory is created");

    let pid_path = directory.join("grandchild.pid");
    let script_path = directory.join("tree.cmd");

    std::fs::write(
        directory.join("grandchild.cjs"),
        "require('node:fs').writeFileSync(process.argv[2], String(process.pid)); setInterval(() => {}, 1000);\n",
    )
    .expect("the grandchild script is written");
    std::fs::write(&script_path, "@node \"%~dp0grandchild.cjs\" %*\r\n")
        .expect("the batch script is written");

    let mut command = CommandWrap::with_new(&script_path, |command| {
        command
            .arg(&pid_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    });

    command.wrap(JobObject);

    let mut child = command.spawn().expect("the batch script spawns");
    let recorded_until = Instant::now() + Duration::from_secs(10);
    let grandchild = loop {
        let recorded = std::fs::read_to_string(&pid_path)
            .ok()
            .and_then(|text| text.trim().parse::<u32>().ok());

        if let Some(pid) = recorded {
            break pid;
        }

        assert!(
            Instant::now() < recorded_until,
            "the grandchild never recorded its pid"
        );

        thread::sleep(POLL_INTERVAL);
    };

    terminate_child(child.as_mut()).expect("the job terminates");

    let listed_until = Instant::now() + Duration::from_secs(2);

    while is_listed(grandchild) && Instant::now() < listed_until {
        thread::sleep(POLL_INTERVAL);
    }

    let listed = is_listed(grandchild);

    if listed {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &grandchild.to_string(), "/F"])
            .output();
    }

    let _ = std::fs::remove_dir_all(&directory);

    assert!(!listed, "the grandchild outlived its job");
}
