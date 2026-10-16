//! Delegated permission answering, end to end: a human arms one Pane's
//! invocation, and the supervisor answers allowlisted permission prompts by
//! typing the provider's own approval reply through the same guarded
//! terminal-delivery path a human answer uses. Every verdict is appended to
//! the event log BEFORE any bytes are typed, the deny floor and the budget
//! withhold, lifecycle changes disarm, and a restart never restores arms.
//!
//! The scripted "agent" is the same job-controlled `sh -c` harness the agent
//! details tests use; its hooks print real connector envelopes from inside
//! its own process group.

use std::io::{BufRead as _, BufReader, Write as _};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use uniterm_proto::{ControlCommand, ControlRequest, CONTROL_API_VERSION};
use uniterm_server::Server;

mod common;

use common::{isolate_state, unique_workspace_name};

/// `run_server` reads `XDG_CONFIG_HOME` on boot; keep it empty so no real
/// user config can leak into a test Workspace. Same shape as isolate_state.
fn isolate_config() {
    static CONFIG: OnceLock<PathBuf> = OnceLock::new();
    let dir = CONFIG.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("uniterm-test-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    });
    std::env::set_var("XDG_CONFIG_HOME", dir);
}

struct Control {
    workspace: String,
    writer: UnixStream,
    reader: BufReader<UnixStream>,
    next_id: u64,
}

impl Control {
    fn connect(socket: &Path) -> Self {
        let control = socket.with_extension("control.sock");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !control.exists() {
            assert!(Instant::now() < deadline, "control socket never appeared");
            thread::sleep(Duration::from_millis(10));
        }
        let writer = UnixStream::connect(&control).unwrap();
        writer
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Control {
            workspace: socket.file_stem().unwrap().to_str().unwrap().into(),
            reader: BufReader::new(writer.try_clone().unwrap()),
            writer,
            next_id: 1,
        }
    }

    /// One request, returning the raw response frame so error codes are
    /// observable. Event frames are skipped.
    fn request_raw(&mut self, command: ControlCommand) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let request = ControlRequest {
            version: CONTROL_API_VERSION,
            id,
            workspace: self.workspace.clone(),
            command,
        };
        serde_json::to_writer(&mut self.writer, &request).unwrap();
        self.writer.write_all(b"\n").unwrap();
        loop {
            let mut line = String::new();
            self.reader.read_line(&mut line).unwrap();
            assert!(!line.is_empty(), "control connection closed");
            let frame: Value = serde_json::from_str(&line).unwrap();
            if frame["frame"] == "response" && frame["id"] == id {
                return frame;
            }
        }
    }

    fn request(&mut self, command: ControlCommand) -> Value {
        let frame = self.request_raw(command);
        assert!(frame["error"].is_null(), "control error: {frame}");
        frame["result"]["data"].clone()
    }

    fn agents(&mut self) -> Value {
        self.request(ControlCommand::AgentList)
    }

    fn agent(&mut self) -> Value {
        self.agents()["entries"][0].clone()
    }

    fn waiting(&mut self) -> Vec<Value> {
        self.request(ControlCommand::WaitingList)["items"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    fn delegation_status(&mut self) -> Vec<Value> {
        self.request(ControlCommand::DelegationStatus { pane: None })["entries"]
            .as_array()
            .cloned()
            .unwrap_or_default()
    }

    fn type_line(&mut self, pane: u64, text: &str) {
        self.request(ControlCommand::PaneSend {
            pane: uniterm_core::PaneId(pane),
            text: format!("{text}\r"),
        });
    }

    fn read(&mut self, pane: u64) -> String {
        self.request(ControlCommand::PaneRead {
            pane: uniterm_core::PaneId(pane),
            lines: 200,
        })["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }

    /// Poll the fleet until `check` holds for the first agent entry.
    fn until(&mut self, what: &str, check: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let agent = self.agent();
            if check(&agent) {
                return agent;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}: {agent}"
            );
            thread::sleep(Duration::from_millis(20));
        }
    }
}

/// Write the envelope the connector would print for one hook invocation.
fn hook_file(dir: &Path, name: &str, hook: Value) -> PathBuf {
    let envelope = uniterm_server::connectors::hook_envelope("claude", hook.to_string().as_bytes())
        .unwrap_or_else(|| panic!("connector rejected {hook}"));
    let path = dir.join(name);
    std::fs::write(&path, envelope).unwrap();
    path
}

fn session_start(session: &str) -> Value {
    json!({
        "hook_event_name": "SessionStart",
        "source": "startup",
        "session_id": session,
        "cwd": "/tmp/demo",
    })
}

fn permission(session: &str, tool: &str, command: &str) -> Value {
    json!({
        "hook_event_name": "PermissionRequest",
        "session_id": session,
        "tool_name": tool,
        "tool_input": {"command": command},
    })
}

fn question(session: &str) -> Value {
    json!({
        "hook_event_name": "Notification",
        "session_id": session,
        "notification_type": "elicitation_dialog",
        "message": "Pick an option",
    })
}

fn plain_file(dir: &Path, name: &str, event: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(
        &path,
        format!("\x1b]777;notify;uniterm://cli-agent;{{\"agent\":\"claude\",\"event\":\"{event}\"}}\x07"),
    )
    .unwrap();
    path
}

fn cat(paths: &[PathBuf]) -> String {
    paths
        .iter()
        .map(|path| format!("cat '{}'", path.display()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Every event appended so far, read back through a cursored subscription.
fn events(socket: &Path) -> Vec<Value> {
    let mut control = Control::connect(socket);
    let current = control.request(ControlCommand::AgentList)["sequence"]
        .as_u64()
        .unwrap();
    let request = ControlRequest {
        version: CONTROL_API_VERSION,
        id: 99,
        workspace: control.workspace.clone(),
        command: ControlCommand::Subscribe { after_sequence: 0 },
    };
    serde_json::to_writer(&mut control.writer, &request).unwrap();
    control.writer.write_all(b"\n").unwrap();
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        control.reader.read_line(&mut line).unwrap();
        assert!(!line.is_empty(), "subscription closed");
        let frame: Value = serde_json::from_str(&line).unwrap();
        if frame["frame"] == "event" {
            let sequence = frame["sequence"].as_u64().unwrap();
            out.push(frame["event"].clone());
            if sequence >= current {
                return out;
            }
        }
    }
}

fn position(events: &[Value], from: usize, test: impl Fn(&Value) -> bool) -> usize {
    events[from..]
        .iter()
        .position(test)
        .map(|index| index + from)
        .unwrap_or_else(|| panic!("event not found after {from}"))
}

fn decisions(events: &[Value]) -> Vec<&Value> {
    events
        .iter()
        .filter_map(|event| event.get("DelegationDecision"))
        .collect()
}

/// A Workspace running the fake agent harness, with one delegation-allow
/// rule per entry in `allow` and the given hourly budget. `files` holds the
/// hook envelopes and the script, so later scripts can reference them all.
struct Harness {
    socket: PathBuf,
    files: PathBuf,
    pane: u64,
    control: Control,
}

fn harness(files: &Path, allow: &[&str], budget: u16, script: &str) -> Harness {
    isolate_state();
    isolate_config();
    let workspace = unique_workspace_name();
    let dir = common::socket_root().join(format!("uniterm-delegation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join(format!("{workspace}.sock"));
    let rules: Vec<uniterm_core::CommandRule> = allow
        .iter()
        .map(|rule| uniterm_core::CommandRule::parse(rule).unwrap())
        .collect();
    let server_socket = socket.clone();
    thread::spawn(move || {
        let (mut server, mut poll) = Server::bind(&server_socket, "/bin/sh", &[], 120, 30).unwrap();
        server.set_config(uniterm_core::Config {
            delegation_allow: rules,
            delegation_max_answers_per_hour: budget,
            ..uniterm_core::Config::default()
        });
        let _ = server.run(&mut poll);
    });
    let mut control = Control::connect(&socket);
    let pane = control.request(ControlCommand::PaneList)["panes"][0]["id"]
        .as_u64()
        .unwrap();
    std::fs::write(files.join("agent.sh"), script).unwrap();
    Harness {
        socket,
        files: files.to_path_buf(),
        pane,
        control,
    }
}

fn run_agent(harness: &mut Harness) {
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("agent.sh").display()),
    );
}

/// Wait until the pane output contains `needle` (or fail after 10 s).
fn until_output(control: &mut Control, pane: u64, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !control.read(pane).contains(needle) {
        assert!(
            Instant::now() < deadline,
            "pane never showed {needle:?}: {}",
            control.read(pane)
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Assert `needle` stays absent from the pane for a short settle window.
fn assert_output_stays_absent(control: &mut Control, pane: u64, needle: &str) {
    let deadline = Instant::now() + Duration::from_millis(800);
    while Instant::now() < deadline {
        assert!(
            !control.read(pane).contains(needle),
            "pane unexpectedly showed {needle:?}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn delegated_permission_is_answered_and_audited() {
    let dir = common::temp_dir("delegation-happy");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    // The prompt is active and unanswered; arming runs one immediate pass.
    let agent = harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    let id = agent["waiting"].as_u64().unwrap();
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    let entries = frame["result"]["data"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["agent"], "claude");
    // Claude's approval reply is "1"; the fake agent echoes what it read.
    until_output(&mut harness.control, harness.pane, "GOT:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["answers_used"], 1);

    // The audit trail: armed, then the Allow decision BEFORE the resolution.
    let log = events(&harness.socket);
    let armed = position(&log, 0, |event| {
        event["DelegationArmed"]["pane"] == harness.pane
    });
    let decided = position(&log, armed, |event| {
        event["DelegationDecision"]["record"]["waiting_id"].as_u64() == Some(id)
            && event["DelegationDecision"]["record"]["verdict"]["outcome"] == "allow"
    });
    let resolved = position(&log, decided, |event| {
        event["WaitingResolved"]["id"].as_u64() == Some(id)
            && event["WaitingResolved"]["resolution"] == "Answered"
    });
    assert!(armed < decided && decided < resolved, "{log:?}");
    // The decision carries the structured facts, never the summary string.
    let record = &log[decided]["DelegationDecision"]["record"];
    assert_eq!(record["tool"], "Bash");
    assert_eq!(record["preview"], "git status");
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn deny_floor_never_answers() {
    let dir = common::temp_dir("delegation-deny");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "rm -rf /tmp/demo"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "rm -rf /tmp/demo"
    });
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    // The item is evaluated immediately and withheld; nothing is typed.
    assert_output_stays_absent(&mut harness.control, harness.pane, "GOT:");
    assert_eq!(harness.control.waiting().len(), 1);
    // `explain` reports the same withhold without changing anything.
    let explained = harness.control.request(ControlCommand::DelegationExplain {
        pane: uniterm_core::PaneId(harness.pane),
    });
    assert_eq!(explained["found"], true);
    assert_eq!(explained["verdict"]["outcome"], "withhold");
    let log = events(&harness.socket);
    let records = decisions(&log);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "withhold");
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn question_is_never_delegated() {
    let dir = common::temp_dir("delegation-question");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", question("s-1"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("question", |agent| agent["status"] == "Question");
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    // Direction questions stay with the human by construction: the arm's
    // immediate pass reaches only a withhold verdict, the item stays, and
    // nothing is ever typed.
    assert_output_stays_absent(&mut harness.control, harness.pane, "GOT:");
    let waiting = harness.control.waiting();
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert_eq!(waiting[0]["kind"], "Question");
    let log = events(&harness.socket);
    let records = decisions(&log);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "withhold");
    assert!(log
        .iter()
        .all(|event| event["WaitingResolved"]["resolution"] != "Answered"));
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn identical_reask_loop_withholds() {
    let dir = common::temp_dir("delegation-loop");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read first; echo \"GOT:$first\"; read second; echo \"AGAIN:$second\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("working", |agent| !agent["status"].is_null());
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    // The first prompt is answered through the Created hook path.
    until_output(&mut harness.control, harness.pane, "GOT:1");
    // The smoothed status stays pinned at Permission, so the reconcile
    // creates a fresh item for the re-ask; the loop guard withholds it
    // rather than typing the same approval twice in a row.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let waiting = harness.control.waiting();
        if waiting.len() == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "re-ask never surfaced");
        thread::sleep(Duration::from_millis(20));
    }
    assert_output_stays_absent(&mut harness.control, harness.pane, "AGAIN:");
    let log = events(&harness.socket);
    let records = decisions(&log);
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[1]["record"]["verdict"]["outcome"], "withhold");
    assert!(
        records[1]["record"]["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{records:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn budget_exhaustion_disarms_until_rearmed() {
    let dir = common::temp_dir("delegation-budget");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let ask_two = hook_file(&dir, "ask-two", permission("s-1", "Bash", "git diff"));
    let idle = plain_file(&dir, "idle", "idle");
    let mut harness = harness(
        &dir,
        &["git status", "git diff"],
        1,
        &format!(
            "{}; read first; echo \"GOT1:$first\"; {}; {}; read second; echo \"GOT2:$second\"; read go",
            cat(&[start, ask]),
            cat(&[idle]),
            cat(&[ask_two])
        )
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    until_output(&mut harness.control, harness.pane, "GOT1:1");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let log = events(&harness.socket);
        if log
            .iter()
            .any(|event| event["DelegationDisarmed"]["reason"] == "budget_exhausted")
        {
            break;
        }
        assert!(Instant::now() < deadline, "never disarmed: {log:?}");
        thread::sleep(Duration::from_millis(50));
    }
    assert!(harness.control.delegation_status().is_empty());
    assert_output_stays_absent(&mut harness.control, harness.pane, "GOT2:");
    // The second item is still active for the human.
    assert_eq!(harness.control.waiting().len(), 1);

    // Re-arming is fresh consent: the budget resets and the active prompt is
    // answered by the arm's immediate pass.
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "re-arm failed: {frame}");
    until_output(&mut harness.control, harness.pane, "GOT2:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["answers_used"], 1);
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn delegation_disarms_on_invocation_change_and_pane_close() {
    let dir = common::temp_dir("delegation-lifecycle");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let restart = hook_file(&dir, "restart", session_start("s-2"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        // The script ends after one line; the foreground returns to the
        // shell, ending the invocation the arm was scoped to.
        &format!("{}; read go", cat(&[start])),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    assert_eq!(harness.control.delegation_status().len(), 1);
    harness.control.type_line(harness.pane, "go");
    // The invocation ends; the arm must not survive into whatever comes next.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if harness.control.delegation_status().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "arm survived the invocation end");
        thread::sleep(Duration::from_millis(20));
    }

    // A fresh invocation can be armed again, and closing the Pane disarms it.
    std::fs::write(
        harness.files.join("second.sh"),
        format!("{}; read go", cat(&[restart])),
    )
    .unwrap();
    thread::sleep(Duration::from_millis(200));
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("second.sh").display()),
    );
    harness
        .control
        .until("rebound", |agent| agent["details"]["session_id"] == "s-2");
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "re-arm failed: {frame}");
    assert_eq!(harness.control.delegation_status().len(), 1);
    // Keep a second Pane alive: closing the Workspace's last Pane stops the
    // server, and with it the control connection.
    harness.control.request(ControlCommand::PaneSplit {
        pane: uniterm_core::PaneId(harness.pane),
        axis: uniterm_proto::SplitAxis::LeftRight,
        background: true,
    });
    harness.control.request(ControlCommand::PaneClose {
        pane: uniterm_core::PaneId(harness.pane),
    });
    assert!(harness.control.delegation_status().is_empty());
    let log = events(&harness.socket);
    let reasons: Vec<&str> = log
        .iter()
        .filter_map(|event| event["DelegationDisarmed"]["reason"].as_str())
        .collect();
    assert_eq!(reasons.len(), 2, "{reasons:?}");
    assert!(
        ["invocation_changed", "agent_exited", "agent_unbound"].contains(&reasons[0]),
        "{reasons:?}"
    );
    assert_eq!(reasons[1], "pane_closed", "{reasons:?}");
}

#[test]
fn arm_requires_confirmation_over_control() {
    let dir = common::temp_dir("delegation-confirm");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!("{}; read go", cat(&[start])),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    // Unconfirmed: refused, and nothing is armed or recorded.
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: false,
    });
    assert_eq!(frame["error"]["code"], "confirmation_required", "{frame}");
    assert!(harness.control.delegation_status().is_empty());
    // Confirmed against a pane with no agent is a plain error, not an arm.
    let missing = 999;
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(missing),
        confirmed: true,
    });
    assert_eq!(frame["error"]["code"], "not_found", "{frame}");
    // Confirmed with a bound agent arms.
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    assert_eq!(harness.control.delegation_status().len(), 1);
    let log = events(&harness.socket);
    assert_eq!(
        log.iter()
            .filter(|event| event.get("DelegationArmed").is_some())
            .count(),
        1,
        "exactly the confirmed arm is recorded: {log:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn an_unarmed_pane_is_byte_identical() {
    let dir = common::temp_dir("delegation-noop");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    let agent = harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    let id = agent["waiting"].as_u64().unwrap();
    // No arm: the human answer path is the only path, and delegation records
    // nothing and types nothing of its own.
    let acted = harness.control.request(ControlCommand::WaitingAct {
        id,
        action: uniterm_proto::WaitingAction::Answer,
        text: "yes".into(),
    });
    assert_eq!(acted["accepted"], true, "{acted}");
    until_output(&mut harness.control, harness.pane, "GOT:yes");
    let log = events(&harness.socket);
    assert!(decisions(&log).is_empty(), "{log:?}");
    assert!(!log
        .iter()
        .any(|event| event.get("DelegationArmed").is_some()
            || event.get("DelegationDisarmed").is_some()));
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn a_restart_never_restores_arms_or_answers() {
    let dir = common::temp_dir("delegation-restart");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        &["git status"],
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: true,
    });
    assert!(frame["error"].is_null(), "arm failed: {frame}");
    until_output(&mut harness.control, harness.pane, "GOT:1");
    assert_eq!(harness.control.delegation_status().len(), 1);

    // Clean stop: the event stream outlives the server; the snapshot does not.
    let mut binary = UnixStream::connect(&harness.socket).unwrap();
    binary
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::KillServer,
        ))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while harness.socket.exists() {
        assert!(Instant::now() < deadline, "server never stopped");
        thread::sleep(Duration::from_millis(20));
    }

    // Boot 2 replays the stream (recover_workspace): delegation events are
    // audit-only, so the server boots and the armed set is empty.
    let socket = harness.socket.clone();
    let server = thread::spawn(move || {
        let _ = uniterm_server::run_server(&socket, "/bin/sh", &[]);
    });
    let mut control = Control::connect(&harness.socket);
    assert!(
        control.delegation_status().is_empty(),
        "re-arming after a restart is the human's fresh consent"
    );
    // The pre-restart audit events survived the stop in the stream.
    let log = events(&harness.socket);
    assert!(log
        .iter()
        .any(|event| event.get("DelegationArmed").is_some()));
    assert!(!decisions(&log).is_empty());

    // A fresh permission prompt on the restored Workspace is never
    // auto-answered: nothing is armed, so the human's item just waits.
    let pane = control.request(ControlCommand::PaneList)["panes"][0]["id"]
        .as_u64()
        .unwrap();
    let files = harness.files.clone();
    std::fs::write(
        files.join("second.sh"),
        format!(
            "{}; read answer; echo \"GOT2:$answer\"; read go",
            cat(&[files.join("start"), files.join("ask")])
        ),
    )
    .unwrap();
    control.type_line(pane, &format!("sh '{}'", files.join("second.sh").display()));
    control.until("permission after restart", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    assert_eq!(control.waiting().len(), 1);
    assert_output_stays_absent(&mut control, pane, "GOT2:");
    let log = events(&harness.socket);
    assert!(
        !decisions(&log).iter().any(|decision| {
            decision["record"]["waiting_id"].as_u64()
                == Some(control.waiting()[0]["id"].as_u64().unwrap())
        }),
        "a restored pane was auto-answered: {log:?}"
    );

    let mut binary = UnixStream::connect(&harness.socket).unwrap();
    binary
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::KillServer,
        ))
        .unwrap();
    let _ = server.join();
}
