//! Delegated permission answering, end to end: a human arms one Pane's
//! invocation (or `delegation-auto-arm` arms every fresh binding as standing
//! consent), and the supervisor answers every permission prompt - structured
//! (OSC 777) or screen-detected - by typing the provider's own approval
//! reply through the same guarded terminal-delivery path a human answer
//! uses. The first answer to a prompt prefers the provider's don't-ask-again
//! reply; a re-surfaced prompt gets the plain yes-reply once; an identical
//! re-ask after that yes is the loop the guard withholds. Questions are
//! never delegated, the hourly budget disarms a spent arm (and auto-arm
//! never re-arms within that invocation), every verdict is appended to the
//! event log BEFORE any bytes are typed, lifecycle changes disarm, and a
//! restart never restores arms.
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
fn isolate_config() -> PathBuf {
    static CONFIG: OnceLock<PathBuf> = OnceLock::new();
    let dir = CONFIG.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("uniterm-test-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    });
    std::env::set_var("XDG_CONFIG_HOME", dir);
    dir.clone()
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

    fn arm(&mut self, pane: u64) {
        let frame = self.request_raw(ControlCommand::DelegationArm {
            pane: uniterm_core::PaneId(pane),
            confirmed: true,
        });
        assert!(frame["error"].is_null(), "arm failed: {frame}");
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
        let deadline = Instant::now() + Duration::from_secs(15);
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

/// A Workspace running the fake agent harness with the given hourly answer
/// budget. `files` holds the hook envelopes and the script, so later scripts
/// can reference them all.
struct Harness {
    socket: PathBuf,
    files: PathBuf,
    pane: u64,
    control: Control,
}

fn harness_with_config(
    files: &Path,
    script: &str,
    configure: impl FnOnce(&mut uniterm_core::Config),
) -> Harness {
    isolate_state();
    isolate_config();
    let workspace = unique_workspace_name();
    let dir = common::socket_root().join(format!("uniterm-delegation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join(format!("{workspace}.sock"));
    let server_socket = socket.clone();
    let mut config = uniterm_core::Config::default();
    configure(&mut config);
    thread::spawn(move || {
        let (mut server, mut poll) = Server::bind(&server_socket, "/bin/sh", &[], 120, 30).unwrap();
        server.set_config(config);
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

fn harness(files: &Path, budget: u16, script: &str) -> Harness {
    harness_with_config(files, script, |config| {
        config.delegation_max_answers_per_hour = budget;
    })
}

/// The auto-arm variant: `delegation-auto-arm` is the human's standing
/// consent, so every fresh binding arms without a control request.
fn harness_auto_arm(files: &Path, budget: u16, script: &str) -> Harness {
    harness_with_config(files, script, |config| {
        config.delegation_auto_arm = true;
        config.delegation_max_answers_per_hour = budget;
    })
}

fn run_agent(harness: &mut Harness) {
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("agent.sh").display()),
    );
}

/// Wait until the pane output contains `needle` (or fail after 15 s).
fn until_output(control: &mut Control, pane: u64, needle: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
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

/// Poll a script-recorded answers file until it contains `needle`. Screen
/// dialogs keep the pane display identical across verdicts, so the scripted
/// agent records what it read to a file instead of echoing it on screen.
fn until_file_contains(path: &Path, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        if content.contains(needle) {
            return content;
        }
        assert!(
            Instant::now() < deadline,
            "answers file never showed {needle:?}: {content}"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

/// Assert `needle` stays absent from the answers file for a settle window.
fn assert_file_stays_absent(path: &Path, needle: &str) {
    assert_file_stays_absent_for(path, needle, Duration::from_millis(800));
}

/// Assert `needle` stays absent from the answers file for `window`.
fn assert_file_stays_absent_for(path: &Path, needle: &str, window: Duration) {
    let deadline = Instant::now() + window;
    while Instant::now() < deadline {
        let content = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            !content.contains(needle),
            "answers file unexpectedly showed {needle:?}: {content}"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

/// Send one Settings patch over the binary attach protocol and return the
/// server's saved Settings projection: the exact live path the client
/// Settings surface uses for every row it owns.
fn settings_apply(
    socket: &Path,
    patch: uniterm_proto::SettingsPatch,
) -> uniterm_proto::SettingsSnapshot {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::Attach {
                term: "xterm-256color".into(),
                cols: 80,
                rows: 24,
            },
        ))
        .unwrap();
    stream
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::SettingsApply(patch),
        ))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut decoder = uniterm_proto::FrameDecoder::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = std::io::Read::read(&mut stream, &mut buf).unwrap();
        assert!(n > 0, "server closed the attach before answering Settings");
        decoder.push(&buf[..n]);
        while let Ok(Some(message)) = decoder.decode::<uniterm_proto::ServerMessage>() {
            if let uniterm_proto::ServerMessage::Settings {
                settings,
                saved,
                error,
            } = message
            {
                // Attach itself answers with a snapshot; the apply is
                // acknowledged only after the atomic save round trips.
                if !saved && error.is_none() {
                    continue;
                }
                assert!(error.is_none(), "settings apply failed: {error:?}");
                assert!(saved, "settings apply reported unsaved");
                return *settings;
            }
        }
    }
}

#[test]
fn delegated_permission_is_answered_and_audited() {
    let dir = common::temp_dir("delegation-happy");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read fallback; echo \"FELL:$fallback\"; read go",
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
    harness.control.arm(harness.pane);
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["agent"], "claude");
    // The first answer prefers Claude's don't-ask-again reply, menu option
    // 2. The pinned status resurfaces the same prompt identity, and that
    // re-ask gets the plain yes-reply exactly once (the loop guard refuses
    // the resurface after that); the fake agent echoes what it read.
    until_output(&mut harness.control, harness.pane, "GOT:2");
    until_output(&mut harness.control, harness.pane, "FELL:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["answers_used"], 2);
    assert_eq!(entries[0]["answers_remaining"], 28);

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
fn an_armed_pane_answers_every_permission_prompt() {
    // There is no command gate: the human's arm is the whole consent, so a
    // prompt about any command is approved and audited like any other.
    let dir = common::temp_dir("delegation-any");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "rm -rf /tmp/demo"));
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read fallback; echo \"FELL:$fallback\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    let agent = harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "rm -rf /tmp/demo"
    });
    let id = agent["waiting"].as_u64().unwrap();
    harness.control.arm(harness.pane);
    // The arm's immediate pass answers the prompt that is already on screen
    // (always-reply first, then the one yes the pinned re-ask is owed).
    until_output(&mut harness.control, harness.pane, "GOT:2");
    until_output(&mut harness.control, harness.pane, "FELL:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["answers_used"], 2);
    // `explain` reaches the same Allow for a fresh evaluation.
    let explained = harness.control.request(ControlCommand::DelegationExplain {
        pane: uniterm_core::PaneId(harness.pane),
    });
    assert_eq!(explained["found"], true);
    let log = events(&harness.socket);
    let records = decisions(&log);
    let decision = records
        .iter()
        .find(|record| record["record"]["waiting_id"].as_u64() == Some(id))
        .unwrap_or_else(|| panic!("no decision for the armed prompt: {records:?}"));
    assert_eq!(decision["record"]["verdict"]["outcome"], "allow");
    assert_eq!(decision["record"]["preview"], "rm -rf /tmp/demo");
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn question_is_never_delegated() {
    let dir = common::temp_dir("delegation-question");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", question("s-1"));
    let mut harness = harness(
        &dir,
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
    harness.control.arm(harness.pane);
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
    // The loop guard reconciled with the always-to-yes escalation: the first
    // answer to a prompt is the always-reply, the identical re-ask gets the
    // plain yes-reply once (the guard must not swallow it), and only the
    // re-ask after THAT yes is the runaway loop the guard withholds.
    let dir = common::temp_dir("delegation-loop");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; read first; echo \"GOT:$first\"; read second; echo \"AGAIN:$second\"; read third; echo \"THIRD:$third\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    harness.control.arm(harness.pane);
    // The first prompt is answered with Claude's always-reply.
    until_output(&mut harness.control, harness.pane, "GOT:2");
    // The smoothed status stays pinned at Permission, so the reconcile
    // creates a fresh item for the re-ask; the always keystroke did not
    // stick for this variant, so the plain yes-reply answers it once.
    until_output(&mut harness.control, harness.pane, "AGAIN:1");
    // The identical prompt resurfacing a third time inside the window is
    // the runaway loop: the guard withholds and the item stays with the
    // human.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let waiting = harness.control.waiting();
        if waiting.len() == 1 {
            break;
        }
        assert!(Instant::now() < deadline, "re-ask never surfaced");
        thread::sleep(Duration::from_millis(20));
    }
    assert_output_stays_absent(&mut harness.control, harness.pane, "THIRD:");
    let log = events(&harness.socket);
    let records = decisions(&log);
    assert_eq!(records.len(), 3, "{records:?}");
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[1]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[2]["record"]["verdict"]["outcome"], "withhold");
    assert!(
        records[2]["record"]["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{records:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn budget_exhaustion_disarms_until_rearmed() {
    // The hourly budget is a core safety rail: with a budget of one, the
    // first answer spends it, the arm disarms itself on the next verdict,
    // and every later prompt waits for the human until a re-arm.
    let dir = common::temp_dir("delegation-budget");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let ask_two = hook_file(&dir, "ask-two", permission("s-1", "Bash", "git diff"));
    let idle = plain_file(&dir, "idle", "idle");
    let mut harness = harness(
        &dir,
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
    harness.control.arm(harness.pane);
    // The one budget unit buys the first answer, Claude's always-reply.
    until_output(&mut harness.control, harness.pane, "GOT1:2");
    let deadline = Instant::now() + Duration::from_secs(15);
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
    // answered by the arm's immediate pass - and with a budget of one, the
    // spent arm disarms itself again on the pinned re-ask.
    harness.control.arm(harness.pane);
    until_output(&mut harness.control, harness.pane, "GOT2:2");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let log = events(&harness.socket);
        if log
            .iter()
            .filter(|event| event["DelegationDisarmed"]["reason"] == "budget_exhausted")
            .count()
            == 2
        {
            break;
        }
        assert!(Instant::now() < deadline, "second arm never spent: {log:?}");
        thread::sleep(Duration::from_millis(50));
    }
    assert!(harness.control.delegation_status().is_empty());
    let log = events(&harness.socket);
    assert_eq!(
        log.iter()
            .filter(|event| event.get("DelegationArmed").is_some())
            .count(),
        2,
        "each arm is its own consent and its own budget: {log:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn auto_arm_never_rearms_a_budget_exhausted_invocation() {
    // Auto-arm is per invocation: a budget_exhausted disarm hands the
    // prompts back to the human for the rest of that invocation, and only a
    // genuinely new binding arms itself again.
    let dir = common::temp_dir("delegation-auto-arm-budget");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let restart = hook_file(&dir, "restart", session_start("s-2"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness_auto_arm(
        &dir,
        1,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    // The fresh binding auto-armed and its one budget unit bought the
    // always-reply; the pinned re-ask then spends the arm.
    until_output(&mut harness.control, harness.pane, "GOT:2");
    let deadline = Instant::now() + Duration::from_secs(15);
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
    // The invocation is still alive and unarmed, and stays that way: only a
    // human re-arm or a new invocation restores answering.
    let settle = Instant::now() + Duration::from_millis(800);
    while Instant::now() < settle {
        assert!(
            harness.control.delegation_status().is_empty(),
            "auto-arm re-created an arm inside the budget-exhausted invocation"
        );
        thread::sleep(Duration::from_millis(50));
    }

    // A fresh invocation in the same Pane auto-arms again with no request.
    std::fs::write(
        harness.files.join("second.sh"),
        format!("{}; read go", cat(&[restart])),
    )
    .unwrap();
    harness.control.type_line(harness.pane, "go");
    thread::sleep(Duration::from_millis(200));
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("second.sh").display()),
    );
    harness
        .control
        .until("rebound", |agent| agent["details"]["session_id"] == "s-2");
    let deadline = Instant::now() + Duration::from_secs(15);
    while harness.control.delegation_status().is_empty() {
        assert!(Instant::now() < deadline, "second binding never auto-armed");
        thread::sleep(Duration::from_millis(20));
    }
    let log = events(&harness.socket);
    assert_eq!(
        log.iter()
            .filter(|event| event.get("DelegationArmed").is_some())
            .count(),
        2,
        "each invocation armed exactly once: {log:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn auto_arm_answers_a_permission_without_a_manual_arm() {
    // `delegation-auto-arm` is standing consent: the fresh binding arms
    // itself and the permission prompt is answered with no control request
    // at all.
    let dir = common::temp_dir("delegation-auto-arm");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let ask = hook_file(&dir, "ask", permission("s-1", "Bash", "git status"));
    let mut harness = harness_auto_arm(
        &dir,
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read fallback; echo \"FELL:$fallback\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    // Always-reply for the first sighting, one yes for the pinned re-ask.
    until_output(&mut harness.control, harness.pane, "GOT:2");
    until_output(&mut harness.control, harness.pane, "FELL:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["agent"], "claude");
    assert_eq!(entries[0]["answers_used"], 2);
    // The audit trail reads as consent, decision, side effect: armed first,
    // then the Allow decision BEFORE the Answered resolution.
    let log = events(&harness.socket);
    let armed = position(&log, 0, |event| {
        event["DelegationArmed"]["pane"] == harness.pane
    });
    let decided = position(&log, armed, |event| {
        event["DelegationDecision"]["record"]["verdict"]["outcome"] == "allow"
    });
    let resolved = position(&log, decided, |event| {
        event["WaitingResolved"]["resolution"] == "Answered"
    });
    assert!(armed < decided && decided < resolved, "{log:?}");
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn auto_arm_rearms_a_new_invocation_after_the_previous_exits() {
    // Auto-arm is per invocation: the arm dies with the process group it was
    // scoped to, and the next fresh binding arms itself in turn.
    let dir = common::temp_dir("delegation-auto-arm-lifecycle");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let restart = hook_file(&dir, "restart", session_start("s-2"));
    let mut harness = harness_auto_arm(&dir, 30, &format!("{}; read go", cat(&[start])));
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    let deadline = Instant::now() + Duration::from_secs(15);
    while harness.control.delegation_status().is_empty() {
        assert!(Instant::now() < deadline, "first binding never auto-armed");
        thread::sleep(Duration::from_millis(20));
    }
    harness.control.type_line(harness.pane, "go");
    // The invocation ends; the arm must not survive into whatever comes next.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if harness.control.delegation_status().is_empty() {
            break;
        }
        assert!(Instant::now() < deadline, "arm survived the invocation end");
        thread::sleep(Duration::from_millis(20));
    }

    // A fresh invocation in the same Pane auto-arms again with no request.
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
    let deadline = Instant::now() + Duration::from_secs(15);
    while harness.control.delegation_status().is_empty() {
        assert!(Instant::now() < deadline, "second binding never auto-armed");
        thread::sleep(Duration::from_millis(20));
    }
    let log = events(&harness.socket);
    assert_eq!(
        log.iter()
            .filter(|event| event.get("DelegationArmed").is_some())
            .count(),
        2,
        "each invocation armed exactly once: {log:?}"
    );
    assert!(
        log.iter()
            .any(|event| event.get("DelegationDisarmed").is_some()),
        "the first arm ended with its invocation: {log:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn yolo_mode_settings_toggle_flips_at_runtime() {
    // The Settings "Yolo Mode" switch is the `delegation-auto-arm` key
    // flipped live through the same atomic writer every Settings row uses:
    // nothing arms retroactively, fresh invocations auto-arm only while it
    // is on, and turning it off leaves current arms alive - the same
    // semantics as a config edit plus reload, with no restart.
    let dir = common::temp_dir("delegation-yolo");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let restart = hook_file(&dir, "restart", session_start("s-2"));
    let third = hook_file(&dir, "third", session_start("s-3"));
    // Boot with the key off (the default): the first binding must not arm.
    let mut harness = harness(&dir, 30, &format!("{}; read go", cat(&[start])));
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    assert!(
        harness.control.delegation_status().is_empty(),
        "the key defaults off"
    );

    // Flip it on at runtime; the saved projection proves the round trip.
    // The already-bound invocation stays unarmed: no retroactive consent.
    let snapshot = settings_apply(
        &harness.socket,
        uniterm_proto::SettingsPatch {
            delegation_auto_arm: Some(true),
            ..Default::default()
        },
    );
    assert!(snapshot.delegation_auto_arm);
    assert!(
        harness.control.delegation_status().is_empty(),
        "the runtime flip armed an already-bound invocation"
    );

    // A fresh invocation in the same Pane auto-arms with no control request.
    std::fs::write(
        harness.files.join("second.sh"),
        format!("{}; read go", cat(&[restart])),
    )
    .unwrap();
    harness.control.type_line(harness.pane, "go");
    thread::sleep(Duration::from_millis(200));
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("second.sh").display()),
    );
    harness
        .control
        .until("rebound", |agent| agent["details"]["session_id"] == "s-2");
    let deadline = Instant::now() + Duration::from_secs(15);
    while harness.control.delegation_status().is_empty() {
        assert!(
            Instant::now() < deadline,
            "fresh binding never auto-armed with Yolo Mode on"
        );
        thread::sleep(Duration::from_millis(20));
    }

    // Flip it back off: the live arm survives, and the next fresh binding
    // does not arm.
    let snapshot = settings_apply(
        &harness.socket,
        uniterm_proto::SettingsPatch {
            delegation_auto_arm: Some(false),
            ..Default::default()
        },
    );
    assert!(!snapshot.delegation_auto_arm);
    assert_eq!(
        harness.control.delegation_status().len(),
        1,
        "turning Yolo Mode off disarmed a live arm"
    );
    std::fs::write(
        harness.files.join("third.sh"),
        format!("{}; read go", cat(&[third])),
    )
    .unwrap();
    harness.control.type_line(harness.pane, "go");
    thread::sleep(Duration::from_millis(200));
    harness.control.type_line(
        harness.pane,
        &format!("sh '{}'", harness.files.join("third.sh").display()),
    );
    harness.control.until("third binding", |agent| {
        agent["details"]["session_id"] == "s-3"
    });
    let settle = Instant::now() + Duration::from_millis(800);
    while Instant::now() < settle {
        assert!(
            harness.control.delegation_status().is_empty(),
            "auto-arm fired while Yolo Mode was off"
        );
        thread::sleep(Duration::from_millis(50));
    }
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn yolo_mode_first_attach_reports_the_boot_config_and_open_writes_nothing() {
    // First-attach and no-op coverage for the Settings "Yolo Mode" switch:
    // a server booted from a config FILE that carries the user's hand edit
    // must report the switch ON on the very first attach, merely opening or
    // refreshing the surface must never rewrite the file, and a patch that
    // does not name `delegation_auto_arm` must leave the key (and the rest
    // of the hand-edited file) untouched.
    isolate_state();
    let config_root = isolate_config();
    let config_dir = config_root.join("uniterm");
    std::fs::create_dir_all(&config_dir).unwrap();
    let config_file = config_dir.join("uniterm.conf");
    std::fs::write(
        &config_file,
        "default-workspace = main\n\
         \n\
         theme = uniterm-dark\n\
         prefix = C-a\n\
         scrollback-limit = 10000\n\
         editor = vi\n\
         \n\
         delegation-max-answers-per-hour = 30\n\
         \n\
         # Delegation (assistant supervisor) - arm per pane with: ut delegate arm PANE\n\
         delegation-max-answers-per-hour = 30\n\
         \n\
         delegation-auto-arm = on\n",
    )
    .unwrap();
    let written = std::fs::read_to_string(&config_file).unwrap();

    // Boot the way the CLI does: `run_server_with_ready` binds, then applies
    // `load_config()` over the defaults before serving.
    let workspace = unique_workspace_name();
    let dir = common::socket_root().join(format!("uniterm-delegation-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join(format!("{workspace}.sock"));
    let server_socket = socket.clone();
    thread::spawn(move || {
        let (mut server, mut poll) = Server::bind(&server_socket, "/bin/sh", &[], 120, 30).unwrap();
        server.set_config(uniterm_server::server::load_config());
        let _ = server.run(&mut poll);
    });
    let mut control = Control::connect(&socket);
    let pane = control.request(ControlCommand::PaneList)["panes"][0]["id"]
        .as_u64()
        .unwrap();

    // The first-attach case: the snapshot pushed on attach, before any
    // Settings request or patch, reports the config file's `on` as ON.
    let mut stream = UnixStream::connect(&socket).unwrap();
    stream
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::Attach {
                term: "xterm-256color".into(),
                cols: 80,
                rows: 24,
            },
        ))
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut decoder = uniterm_proto::FrameDecoder::new();
    let next_settings = |stream: &mut UnixStream,
                         decoder: &mut uniterm_proto::FrameDecoder|
     -> (uniterm_proto::SettingsSnapshot, bool, Option<String>) {
        let mut buf = [0u8; 65536];
        loop {
            let n = std::io::Read::read(stream, &mut buf).unwrap();
            assert!(n > 0, "server closed the attach before a Settings reply");
            decoder.push(&buf[..n]);
            while let Ok(Some(message)) = decoder.decode::<uniterm_proto::ServerMessage>() {
                if let uniterm_proto::ServerMessage::Settings {
                    settings,
                    saved,
                    error,
                } = message
                {
                    return (*settings, saved, error);
                }
            }
        }
    };
    let (snapshot, saved, error) = next_settings(&mut stream, &mut decoder);
    assert!(!saved, "the attach snapshot is not a save acknowledgement");
    assert!(error.is_none(), "attach snapshot error: {error:?}");
    assert!(
        snapshot.delegation_auto_arm,
        "first attach reported Yolo Mode off for a config file that says on"
    );

    // The no-op case: opening/refreshing the surface answers from live state
    // and must not touch the file at all.
    stream
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::Settings,
        ))
        .unwrap();
    let (snapshot, _, error) = next_settings(&mut stream, &mut decoder);
    assert!(error.is_none(), "settings refresh error: {error:?}");
    assert!(snapshot.delegation_auto_arm);
    thread::sleep(Duration::from_millis(400));
    assert_eq!(
        std::fs::read_to_string(&config_file).unwrap(),
        written,
        "opening the Settings surface rewrote the config file"
    );

    // Standing consent works from the file boot: a fresh binding arms with
    // no control request.
    let files = common::temp_dir("delegation-yolo-boot");
    let start = hook_file(&files, "start", session_start("s-boot"));
    std::fs::write(
        files.join("agent.sh"),
        format!("{}; read go", cat(&[start])),
    )
    .unwrap();
    control.type_line(pane, &format!("sh '{}'", files.join("agent.sh").display()));
    control.until("bound", |agent| agent["details"]["session_id"] == "s-boot");
    let deadline = Instant::now() + Duration::from_secs(15);
    while control.delegation_status().is_empty() {
        assert!(
            Instant::now() < deadline,
            "a file-booted `delegation-auto-arm = on` never armed a fresh binding"
        );
        thread::sleep(Duration::from_millis(20));
    }
    control.type_line(pane, "go");

    // The stale-patch case: an apply that does not name the key cannot zero
    // it, in the reply or on disk, and the merge preserves the hand-edited
    // lines around it.
    let (snapshot, saved, error) = {
        stream
            .write_all(&uniterm_proto::encode_frame(
                &uniterm_proto::ClientMessage::SettingsApply(uniterm_proto::SettingsPatch {
                    scrollback_limit: Some(4_242),
                    ..Default::default()
                }),
            ))
            .unwrap();
        // Skip the duplicate focus-style pushes; the apply acknowledgement
        // arrives only after the atomic save round trips.
        loop {
            let (snapshot, saved, error) = next_settings(&mut stream, &mut decoder);
            if saved || error.is_some() {
                break (snapshot, saved, error);
            }
        }
    };
    assert!(error.is_none(), "unrelated patch failed: {error:?}");
    assert!(saved, "unrelated patch was not persisted");
    assert!(
        snapshot.delegation_auto_arm,
        "an unrelated patch flipped Yolo Mode off in the live projection"
    );
    let settled = std::fs::read_to_string(&config_file).unwrap();
    assert!(
        uniterm_core::Config::parse(&settled).delegation_auto_arm,
        "an unrelated patch rewrote the file's delegation-auto-arm key: {settled}"
    );
    assert!(
        settled.contains("# Delegation (assistant supervisor)")
            && settled.contains("default-workspace = main"),
        "the atomic save dropped hand-edited lines: {settled}"
    );
}

#[test]
fn screen_detected_permission_is_answered_with_a_prompt_fingerprint() {
    // A permission prompt detected by the provider's screen rules carries no
    // structured payload. It is answered like any other: the audit record's
    // tool is "unknown" and its preview is a bounded fingerprint of the live
    // prompt region - the actual dialog content, not the waiting item's
    // rule-text summary, which is identical for every dialog one provider
    // raises. The scripted agent keeps the screen byte-identical across
    // verdicts (echo off, answers recorded to a file), so the pinned
    // resurface sees exactly the prompt it answered.
    let dir = common::temp_dir("delegation-screen");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; printf '\\033[2J\\033[HDo you want to proceed?\\n  $ rm -rf /tmp/demo\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n'; read first; echo \"FIRST:$first\" >> '{}'; read second; echo \"SECOND:$second\" >> '{}'; read go",
            cat(&[start]),
            answers.display(),
            answers.display()
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    // The screen rule matches after the permission dwell (about 5 s).
    let agent = harness
        .control
        .until("screen permission", |agent| agent["status"] == "Permission");
    assert!(
        agent["details"]["pending_permission"].is_null(),
        "a screen-detected prompt has no structured payload: {agent}"
    );
    let waiting = harness.control.waiting();
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert_eq!(waiting[0]["kind"], "Permission");
    let summary = waiting[0]["summary"].as_str().unwrap().to_string();
    harness.control.arm(harness.pane);
    // The screen-pinned status resurfaces the prompt like any other pin:
    // always-reply, one yes, then the loop guard's withhold.
    until_file_contains(&answers, "FIRST:2");
    until_file_contains(&answers, "SECOND:1");
    let deadline = Instant::now() + Duration::from_secs(15);
    let log = loop {
        let log = events(&harness.socket);
        if decisions(&log).len() >= 3 {
            break log;
        }
        assert!(Instant::now() < deadline, "decisions never recorded");
        thread::sleep(Duration::from_millis(50));
    };
    let records = decisions(&log);
    assert_eq!(records.len(), 3, "{records:?}");
    for record in &records {
        assert_eq!(record["record"]["tool"], "unknown");
        let preview = record["record"]["preview"].as_str().unwrap();
        // Distinguishing content, never the bare rule-text summary.
        assert_ne!(preview, summary, "{records:?}");
        assert!(preview.contains("Do you want to proceed?"), "{preview}");
        assert!(preview.contains("rm -rf /tmp/demo"), "{preview}");
        assert!(preview.contains("Esc to cancel"), "{preview}");
    }
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[1]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[2]["record"]["verdict"]["outcome"], "withhold");
    assert!(
        records[2]["record"]["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{records:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn distinct_screen_dialogs_inside_the_loop_window_are_both_answered() {
    // Regression: two DIFFERENT screen-detected dialogs inside the 60 s loop
    // window share the provider's matched rule text, so a summary-keyed
    // identity withheld the second as a re-ask and a hook-less agent got one
    // auto-answer per minute. The prompt-region fingerprint tells them
    // apart, so both are answered. The screen goes blank between the
    // dialogs (long enough to idle the smoothed status), which is what
    // surfaces the second dialog as a fresh waiting item.
    let dir = common::temp_dir("delegation-screen-distinct");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {start}; printf '\\033[2J\\033[HDo you want to proceed?\\n  $ rm -rf /tmp/demo\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n'; read a1; echo \"A1:$a1\" >> '{out}'; read a2; echo \"A2:$a2\" >> '{out}'; printf '\\033[2J\\033[H'; sleep 2; printf 'Do you want to proceed?\\n  $ ls -l /var/tmp\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n'; read b1; echo \"B1:$b1\" >> '{out}'; read b2; echo \"B2:$b2\" >> '{out}'; read go",
            start = cat(&[start]),
            out = answers.display()
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    harness.control.arm(harness.pane);
    // Dialog A: always-reply, then the pinned resurface's one yes.
    until_file_contains(&answers, "A1:2");
    until_file_contains(&answers, "A2:1");
    // Dialog B inside the same loop window: answered on its own identity,
    // always-reply first, never withheld as a re-ask of A.
    until_file_contains(&answers, "B1:2");
    let content = until_file_contains(&answers, "B2:1");
    assert!(
        content.lines().collect::<Vec<_>>() == ["A1:2", "A2:1", "B1:2", "B2:1"],
        "{content}"
    );
    // The audit trail keys on dialog content: an allow whose preview names
    // A's command, then an allow whose preview names B's, both distinct
    // from the rule-text summary the waiting item carries.
    let deadline = Instant::now() + Duration::from_secs(15);
    let log = loop {
        let log = events(&harness.socket);
        let allow_count = decisions(&log)
            .iter()
            .filter(|record| record["record"]["verdict"]["outcome"] == "allow")
            .count();
        if allow_count >= 4 {
            break log;
        }
        assert!(Instant::now() < deadline, "allows never recorded");
        thread::sleep(Duration::from_millis(50));
    };
    let records = decisions(&log);
    let allows: Vec<_> = records
        .iter()
        .filter(|record| record["record"]["verdict"]["outcome"] == "allow")
        .collect();
    assert!(
        allows[..2].iter().all(|record| record["record"]["preview"]
            .as_str()
            .unwrap()
            .contains("rm -rf /tmp/demo")),
        "dialog A's allows carry its command: {allows:?}"
    );
    assert!(
        allows[2..].iter().all(|record| record["record"]["preview"]
            .as_str()
            .unwrap()
            .contains("ls -l /var/tmp")),
        "dialog B's allows carry its command: {allows:?}"
    );
    assert!(
        allows.iter().all(|record| record["record"]["preview"]
            .as_str()
            .is_some_and(|preview| !preview.contains("grid matched"))),
        "an allow fell back to the rule-text summary for identity: {records:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn identical_screen_dialog_reask_still_withholds() {
    // The other half of the loop-guard contract: a genuinely re-asked
    // IDENTICAL screen dialog keeps one fingerprint, so after the
    // always-reply and the one plain yes the guard still treats the
    // surfacing after that yes as a runaway loop and withholds it.
    let dir = common::temp_dir("delegation-screen-reask");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {start}; printf '\\033[2J\\033[HDo you want to proceed?\\n  $ git push --force\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n'; read a1; echo \"A1:$a1\" >> '{out}'; read a2; echo \"A2:$a2\" >> '{out}'; printf '\\033[2J\\033[H'; sleep 2; printf 'Do you want to proceed?\\n  $ git push --force\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n'; read a3; echo \"A3:$a3\" >> '{out}'",
            start = cat(&[start]),
            out = answers.display()
        ),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    harness.control.arm(harness.pane);
    // The first showing gets the always-reply, its pinned resurface one yes.
    until_file_contains(&answers, "A1:2");
    until_file_contains(&answers, "A2:1");
    // The byte-identical re-ask surfaces as a fresh waiting item after the
    // blank interval, and the guard withholds it: no third answer is typed.
    let deadline = Instant::now() + Duration::from_secs(30);
    let log = loop {
        let log = events(&harness.socket);
        let records = decisions(&log);
        if records.len() >= 4
            && records
                .last()
                .is_some_and(|record| record["record"]["verdict"]["outcome"] == "withhold")
        {
            break log;
        }
        assert!(
            Instant::now() < deadline,
            "the identical re-ask was never withheld: {records:?}"
        );
        thread::sleep(Duration::from_millis(50));
    };
    assert_file_stays_absent(&answers, "A3:");
    let records = decisions(&log);
    assert_eq!(records[0]["record"]["verdict"]["outcome"], "allow");
    assert_eq!(records[1]["record"]["verdict"]["outcome"], "allow");
    let last = records.last().unwrap();
    assert_eq!(last["record"]["verdict"]["outcome"], "withhold");
    assert!(
        last["record"]["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{records:?}"
    );
    assert!(
        last["record"]["preview"]
            .as_str()
            .unwrap()
            .contains("git push --force"),
        "the withheld re-ask keys on the dialog content: {records:?}"
    );
    harness.control.type_line(harness.pane, "go");
}

#[test]
fn delegation_disarms_on_invocation_change_and_pane_close() {
    let dir = common::temp_dir("delegation-lifecycle");
    let start = hook_file(&dir, "start", session_start("s-1"));
    let restart = hook_file(&dir, "restart", session_start("s-2"));
    let mut harness = harness(
        &dir,
        30,
        // The script ends after one line; the foreground returns to the
        // shell, ending the invocation the arm was scoped to.
        &format!("{}; read go", cat(&[start])),
    );
    run_agent(&mut harness);
    harness
        .control
        .until("bound", |agent| agent["details"]["session_id"] == "s-1");
    harness.control.arm(harness.pane);
    assert_eq!(harness.control.delegation_status().len(), 1);
    harness.control.type_line(harness.pane, "go");
    // The invocation ends; the arm must not survive into whatever comes next.
    let deadline = Instant::now() + Duration::from_secs(15);
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
    harness.control.arm(harness.pane);
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
    let mut harness = harness(&dir, 30, &format!("{}; read go", cat(&[start])));
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
    harness.control.arm(harness.pane);
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
        30,
        &format!(
            "{}; read answer; echo \"GOT:$answer\"; read fallback; echo \"FELL:$fallback\"; read go",
            cat(&[start, ask])
        ),
    );
    run_agent(&mut harness);
    harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    harness.control.arm(harness.pane);
    until_output(&mut harness.control, harness.pane, "GOT:2");
    until_output(&mut harness.control, harness.pane, "FELL:1");
    assert_eq!(harness.control.delegation_status().len(), 1);

    // Clean stop: the event stream outlives the server; the snapshot does not.
    let mut binary = UnixStream::connect(&harness.socket).unwrap();
    binary
        .write_all(&uniterm_proto::encode_frame(
            &uniterm_proto::ClientMessage::KillServer,
        ))
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
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
