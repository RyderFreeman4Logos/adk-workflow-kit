//! Fixed OS-negative fixture; never a production worker or a model execution tool.
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

#[derive(Deserialize)]
struct Request {
    batch: Batch,
}
#[derive(Deserialize)]
struct Batch {
    steps: Vec<Call>,
}
#[derive(Deserialize)]
struct Call {
    tool: String,
    arguments: BTreeMap<String, String>,
}

fn inspect(call: &Call) -> Result<(), Box<dyn std::error::Error>> {
    match call.tool.as_str() {
        "boundary_files" => {
            let file = call.arguments.get("file").ok_or("file missing")?;
            let sibling = call.arguments.get("sibling").ok_or("sibling missing")?;
            if fs::read(file).is_ok() || fs::read(sibling).is_ok() {
                return Err("host file visible".into());
            }
            if ["/input", "/package", "/skills", "/refs", "/out"]
                .iter()
                .any(|p| std::path::Path::new(p).exists())
            {
                return Err("host mount visible".into());
            }
            if fs::read_dir("/work")?.next().is_some() {
                return Err("host work visible".into());
            }
            std::os::unix::fs::symlink(file, "/work/escape")?;
            if fs::read("/work/escape").is_ok() {
                return Err("symlink escaped".into());
            }
        }
        "boundary_network" => {
            let address: SocketAddr = call
                .arguments
                .get("address")
                .ok_or("address missing")?
                .parse()?;
            if !address.ip().is_loopback() {
                return Err("fixture address must be loopback".into());
            }
            if TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_ok() {
                return Err("host listener reachable".into());
            }
        }
        "boundary_pid" => {
            let pid: u32 = call.arguments.get("pid").ok_or("pid missing")?.parse()?;
            if fs::read(format!("/proc/{pid}/stat")).is_ok() || fs::read("/proc/1/stat").is_err() {
                return Err("host PID visible or proc absent".into());
            }
        }
        "boundary_env" => {
            let env = std::env::vars_os().collect::<Vec<_>>();
            if env
                != [(
                    std::ffi::OsString::from("PWD"),
                    std::ffi::OsString::from("/work"),
                )]
            {
                return Err("host environment inherited".into());
            }
        }
        "boundary_fd" => {
            for fd in 3..256 {
                // SAFETY: F_GETFD inspects an integer descriptor without dereferencing memory.
                if unsafe { libc::fcntl(fd, libc::F_GETFD) } != -1 {
                    return Err("extra FD inherited".into());
                }
            }
        }
        "boundary_process" => {
            // SAFETY: after fork the fixture children only call fork/pause/_exit;
            // they never allocate, log, lock, or return into Rust cleanup.
            unsafe {
                let child = libc::fork();
                if child == -1 {
                    return Err("fixture fork failed".into());
                }
                if child == 0 {
                    if libc::fork() == -1 {
                        libc::_exit(71);
                    }
                    loop {
                        libc::pause();
                    }
                }
                loop {
                    libc::pause();
                }
            }
        }
        "boundary_output" => {
            let block = [b'x'; 8192];
            loop {
                std::io::stdout().write_all(&block)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = Vec::new();
    std::io::stdin().take(65_537).read_to_end(&mut input)?;
    let request: Request = serde_json::from_slice(&input)?;
    let first = request
        .batch
        .steps
        .first()
        .ok_or("fixture action missing")?;
    inspect(first)?;
    let mut output = Vec::new();
    workflow_runtime::behavioral::worker::run_worker(&input[..], &mut output)?;
    let mut value: serde_json::Value = serde_json::from_slice(&output)?;
    match first.tool.as_str() {
        "wrong_protocol" => value["protocol"] = 9.into(),
        "wrong_scope" => value["scope"] = "sha256:forged".into(),
        "wrong_sequence" => value["events"][0]["seq"] = 9.into(),
        "wrong_prefix" => value["prefix_digest"] = "sha256:forged".into(),
        "extra_report" => value["untrusted_extra"] = true.into(),
        "extra_stop" => value["stop"]["untrusted_extra"] = true.into(),
        _ => {}
    }
    if first.tool == "duplicate_report" {
        let json = serde_json::to_string(&value)?.replacen(
            "\"protocol\":1",
            "\"protocol\":1,\"protocol\":1",
            1,
        );
        std::io::stdout().write_all(json.as_bytes())?;
        return Ok(());
    }
    serde_json::to_writer(std::io::stdout().lock(), &value)?;
    Ok(())
}
fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(_) => std::process::ExitCode::FAILURE,
    }
}
