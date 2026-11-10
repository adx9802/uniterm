//! Delegated permission answering, end to end: a human arms one Pane's
//! invocation (or Yolo Mode arms every binding), and the supervisor answers
//! permission prompts - structured (OSC 777) or screen-detected - by typing
//! the provider's approval reply. The first answer prefers the provider's
//! don't-ask-again reply, a re-surfaced prompt gets the plain yes once, and
//! an identical re-ask after that yes is the loop the guard withholds.
//!
//! The scripted "agent" is a job-controlled `sh -c` harness whose hooks print
//! real connector envelopes from inside its own process group.

use std::io::Write as _;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use uniterm_proto::ControlCommand;

mod common;
#[path = "common/control.rs"]
mod control;

use control::*;

fn start_file(dir: &Path, provider: &str, session: &str) -> PathBuf {
    hook_file(dir, "start", provider, session_start(session))
}

fn permission_file(dir: &Path, name: &str, command: &str) -> PathBuf {
    hook_file(
        dir,
        name,
        "claude",
        json!({
            "hook_event_name": "PermissionRequest",
            "session_id": "s-1",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        }),
    )
}

/// A `printf` that clears the screen and draws Claude's permission dialog.
fn claude_dialog(command: &str, footer: bool) -> String {
    let footer = if footer {
        "Esc to cancel · Tab to amend\\n"
    } else {
        ""
    };
    format!("printf '\\033[2J\\033[HDo you want to proceed?\\n  $ {command}\\n❯ 1. Yes\\n  2. No\\n{footer}'")
}

fn disarmed_for(log: &[Value], reason: &str) -> usize {
    log.iter()
        .filter(|event| event["DelegationDisarmed"]["reason"] == reason)
        .count()
}

fn decisions(events: &[Value]) -> Vec<Value> {
    events
        .iter()
        .filter_map(|event| event.get("DelegationDecision"))
        .map(|decision| decision["record"].clone())
        .collect()
}

fn outcomes(records: &[Value]) -> Vec<&str> {
    records
        .iter()
        .map(|record| record["verdict"]["outcome"].as_str().unwrap())
        .collect()
}

fn preview(record: &Value) -> &str {
    record["preview"].as_str().unwrap()
}

/// The log once `ready` holds for its decision records.
fn wait_decisions(socket: &Path, ready: impl Fn(&[Value]) -> bool) -> Vec<Value> {
    let mut log = Vec::new();
    wait_for("decisions", TIMEOUT, || {
        log = events(socket);
        ready(&decisions(&log))
    });
    log
}

/// Always-reply, one plain yes, then the loop withhold.
fn assert_answered_then_loop(records: &[Value]) {
    assert_eq!(
        outcomes(records),
        ["allow", "allow", "withhold"],
        "{records:?}"
    );
    assert!(
        records[2]["verdict"]["reason"]
            .as_str()
            .unwrap()
            .contains("loop"),
        "{records:?}"
    );
}

/// A Workspace running the fake agent harness; `files` holds the hook
/// envelopes and the scripts.
struct Harness {
    socket: PathBuf,
    files: PathBuf,
    pane: u64,
    control: Control,
}

impl Harness {
    fn new(files: &Path, budget: u16, auto_arm: bool) -> Self {
        let (socket, control, pane) = start_server(uniterm_core::Config {
            delegation_max_answers_per_hour: budget,
            delegation_auto_arm: auto_arm,
            ..Default::default()
        });
        Harness {
            socket,
            files: files.to_path_buf(),
            pane,
            control,
        }
    }

    /// Write `script` as `name` and run it in the Pane.
    fn run(&mut self, name: &str, script: &str) {
        let path = self.files.join(name);
        std::fs::write(&path, script).unwrap();
        self.control
            .type_line(self.pane, &format!("sh '{}'", path.display()));
    }

    fn until_output(&mut self, needle: &str) {
        self.control.until_output(self.pane, needle);
    }

    fn arm(&mut self) {
        self.control.arm(self.pane);
    }

    fn type_line(&mut self, text: &str) {
        self.control.type_line(self.pane, text);
    }

    fn events(&self) -> Vec<Value> {
        events(&self.socket)
    }
}

fn harness(files: &Path, budget: u16, script: &str) -> Harness {
    let mut harness = Harness::new(files, budget, false);
    harness.run("agent.sh", script);
    harness
}

fn harness_auto_arm(files: &Path, budget: u16, script: &str) -> Harness {
    let mut harness = Harness::new(files, budget, true);
    harness.run("agent.sh", script);
    harness
}

fn auto_arm_patch(on: bool) -> uniterm_proto::SettingsPatch {
    uniterm_proto::SettingsPatch {
        delegation_auto_arm: Some(on),
        ..Default::default()
    }
}

#[test]
fn delegated_permission_is_answered_and_audited() {
    let dir = common::temp_dir("delegation-happy");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT", "FELL"], None)
        ),
    );
    // The prompt is active and unanswered; arming runs one immediate pass.
    let agent = harness.control.until("permission", |agent| {
        agent["status"] == "Permission"
            && agent["details"]["pending_permission"]["preview"] == "git status"
    });
    let id = agent["waiting"].as_u64().unwrap();
    harness.arm();
    // Claude's don't-ask-again reply (option 2) first; the pinned status
    // resurfaces the same prompt, which gets the plain yes once.
    harness.until_output("GOT:2");
    harness.until_output("FELL:1");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["agent"], "claude");
    assert_eq!(entries[0]["answers_used"], 2);
    assert_eq!(entries[0]["answers_remaining"], 28);
    let explained = harness.control.request(ControlCommand::DelegationExplain {
        pane: uniterm_core::PaneId(harness.pane),
    });
    assert_eq!(explained["found"], true);

    // Armed, then the Allow decision BEFORE the resolution.
    let log = harness.events();
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
    harness.type_line("go");
}

#[test]
fn question_is_never_delegated() {
    let dir = common::temp_dir("delegation-question");
    let start = start_file(&dir, "claude", "s-1");
    let ask = hook_file(
        &dir,
        "ask",
        "claude",
        json!({
            "hook_event_name": "Notification",
            "session_id": "s-1",
            "notification_type": "elicitation_dialog",
            "message": "Pick an option",
        }),
    );
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT"], None)
        ),
    );
    harness
        .control
        .until("question", |agent| agent["status"] == "Question");
    harness.arm();
    harness
        .control
        .assert_output_stays_absent(harness.pane, "GOT:");
    let waiting = harness.control.waiting();
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    assert_eq!(waiting[0]["kind"], "Question");
    let log = harness.events();
    assert_eq!(outcomes(&decisions(&log)), ["withhold"]);
    assert!(log
        .iter()
        .all(|event| event["WaitingResolved"]["resolution"] != "Answered"));
    harness.type_line("go");
}

#[test]
fn identical_reask_loop_withholds() {
    // The always-reply, then the plain yes once (the guard must not swallow
    // it), and only the re-ask after THAT yes is the loop.
    let dir = common::temp_dir("delegation-loop");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT", "AGAIN", "THIRD"], None)
        ),
    );
    harness.control.until_bound("s-1");
    harness.arm();
    harness.until_output("GOT:2");
    harness.until_output("AGAIN:1");
    wait_for("the re-ask", TIMEOUT, || {
        harness.control.waiting().len() == 1
    });
    harness
        .control
        .assert_output_stays_absent(harness.pane, "THIRD:");
    assert_answered_then_loop(&decisions(&harness.events()));
    harness.type_line("go");
}

#[test]
fn budget_exhaustion_disarms_until_rearmed() {
    // With a budget of one, the first answer spends it, the arm disarms on
    // the next verdict, and later prompts wait for the human until a re-arm.
    let dir = common::temp_dir("delegation-budget");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let ask_two = permission_file(&dir, "ask-two", "git diff");
    let idle = plain_file(&dir, "idle", "idle");
    let mut harness = harness(
        &dir,
        1,
        &format!(
            "{}; {}; {}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT1"], None),
            cat(&[&idle, &ask_two]),
            echo_reads(&["GOT2"], None),
        ),
    );
    harness.control.until_bound("s-1");
    harness.arm();
    harness.until_output("GOT1:2");
    wait_for("the budget disarm", TIMEOUT, || {
        disarmed_for(&harness.events(), "budget_exhausted") == 1
    });
    assert!(harness.control.delegation_status().is_empty());
    harness
        .control
        .assert_output_stays_absent(harness.pane, "GOT2:");
    assert_eq!(harness.control.waiting().len(), 1);

    // Re-arming is fresh consent with a fresh budget, spent again at once.
    harness.arm();
    harness.until_output("GOT2:2");
    wait_for("the second budget disarm", TIMEOUT, || {
        disarmed_for(&harness.events(), "budget_exhausted") == 2
    });
    assert!(harness.control.delegation_status().is_empty());
    assert_eq!(count(&harness.events(), "DelegationArmed"), 2);
    harness.type_line("go");
}

#[test]
fn yolo_mode_has_no_hourly_budget() {
    // With a budget of one, the auto arm keeps answering every prompt with no
    // manual arm, never disarms, and reports itself unlimited.
    let dir = common::temp_dir("delegation-yolo-budget");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let ask_two = permission_file(&dir, "ask-two", "git diff");
    let idle = plain_file(&dir, "idle", "idle");
    let mut harness = harness_auto_arm(
        &dir,
        1,
        &format!(
            "{}; {}; {}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["A"], None),
            cat(&[&idle, &ask_two]),
            echo_reads(&["B", "C", "D"], None),
        ),
    );
    harness.until_output("A:2");
    harness.until_output("D:");
    let log = harness.events();
    let allows = outcomes(&decisions(&log))
        .into_iter()
        .filter(|outcome| *outcome == "allow")
        .count();
    assert!(allows >= 3, "a budget of one capped Yolo Mode: {log:?}");
    assert_eq!(disarmed_for(&log, "budget_exhausted"), 0, "{log:?}");
    assert_eq!(count(&log, "DelegationArmed"), 1, "{log:?}");
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "{entries:?}");
    assert_eq!(entries[0]["unlimited"], true, "{entries:?}");
    harness.type_line("go");
}

#[test]
fn yolo_mode_honours_an_explicit_disarm_for_that_invocation() {
    let dir = common::temp_dir("delegation-yolo-disarm");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let mut harness = harness_auto_arm(
        &dir,
        30,
        &format!(
            "{}; read go1; {}; {}; read go",
            cat(&[&start]),
            cat(&[&ask]),
            echo_reads(&["A"], None)
        ),
    );
    harness.control.until_bound("s-1");
    harness.control.wait_armed();
    harness.control.request(ControlCommand::DelegationDisarm {
        pane: uniterm_core::PaneId(harness.pane),
    });
    harness.type_line("go1");
    harness
        .control
        .until("permission", |agent| agent["status"] == "Permission");
    harness
        .control
        .assert_output_stays_absent(harness.pane, "A:");
    assert!(harness.control.delegation_status().is_empty());
    assert_eq!(harness.control.waiting().len(), 1);
    let log = harness.events();
    assert!(decisions(&log).is_empty(), "{log:?}");
    assert_eq!(count(&log, "DelegationArmed"), 1, "{log:?}");
    harness.type_line("x");
    harness.until_output("A:x");
    harness.type_line("go");
}

#[test]
fn yolo_mode_settings_toggle_flips_at_runtime() {
    // Turning the switch on arms every bound Pane, re-applying it is a
    // no-op, fresh invocations auto-arm only while it is on, and turning it
    // off leaves current arms alive.
    let dir = common::temp_dir("delegation-yolo");
    let start = start_file(&dir, "claude", "s-1");
    let restart = hook_file(&dir, "restart", "claude", session_start("s-2"));
    let third = hook_file(&dir, "third", "claude", session_start("s-3"));
    let mut harness = harness(&dir, 30, &format!("{}; read go", cat(&[&start])));
    harness.control.until_bound("s-1");
    assert!(harness.control.delegation_status().is_empty());

    assert!(settings_apply(&harness.socket, auto_arm_patch(true)).delegation_auto_arm);
    let entries = harness.control.delegation_status();
    assert_eq!(entries.len(), 1, "the flip left a bound Pane unarmed");
    assert_eq!(entries[0]["unlimited"], true, "{entries:?}");
    settings_apply(&harness.socket, auto_arm_patch(true));
    assert_eq!(count(&harness.events(), "DelegationArmed"), 1);

    // The arm ends with its invocation; the next one auto-arms.
    harness.type_line("go");
    wait_for("the invocation-end disarm", TIMEOUT, || {
        harness.control.delegation_status().is_empty()
    });
    harness.run("second.sh", &format!("{}; read go", cat(&[&restart])));
    harness.control.until_bound("s-2");
    harness.control.wait_armed();

    assert!(!settings_apply(&harness.socket, auto_arm_patch(false)).delegation_auto_arm);
    assert_eq!(
        harness.control.delegation_status().len(),
        1,
        "turning Yolo Mode off disarmed a live arm"
    );
    harness.type_line("go");
    thread::sleep(Duration::from_millis(200));
    harness.run("third.sh", &format!("{}; read go", cat(&[&third])));
    harness.control.until_bound("s-3");
    holds_for("auto-arm fired while Yolo Mode was off", SETTLE, || {
        harness.control.delegation_status().is_empty()
    });
    harness.type_line("go");
}

#[test]
fn fast_settle_answers_a_complete_settled_dialog_before_the_dwell() {
    // A complete, quiet dialog on an armed Pane is answered in ~0.1 s
    // instead of the 5 s dwell; the pinned resurface then rides the dwell.
    let dir = common::temp_dir("delegation-settle");
    let start = start_file(&dir, "claude", "s-1");
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; {}; {}; read go",
            cat(&[&start]),
            claude_dialog("rm -rf /tmp/demo", true),
            echo_reads(&["FIRST", "SECOND"], Some(&answers))
        ),
    );
    harness.control.until_bound("s-1");
    let armed_at = Instant::now();
    harness.arm();
    wait_until_file_contains(&answers, "FIRST:2");
    assert!(armed_at.elapsed() < Duration::from_secs(3));
    wait_until_file_contains(&answers, "SECOND:1");
    let records = decisions(&wait_decisions(&harness.socket, |r| r.len() >= 3));
    assert_answered_then_loop(&records);
    assert!(records
        .iter()
        .all(|record| preview(record).contains("rm -rf /tmp/demo")));
    harness.type_line("go");
}

#[test]
fn fast_settle_waits_for_the_region_to_stay_quiet() {
    // Repaints closer together than the 0.1 s settle keep re-arming the
    // tick, so the answer lands only after the last repaint.
    let dir = common::temp_dir("delegation-flicker");
    let start = start_file(&dir, "claude", "s-1");
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; read release; i=0; while [ $i -lt 40 ]; do printf '\\033[2J\\033[HDo you want to proceed?\\n  $ rm -rf /tmp/demo (tick %s)\\n❯ 1. Yes\\n  2. No\\nEsc to cancel · Tab to amend\\n' \"$i\"; i=$((i+1)); sleep 0.04; done; {}; read go",
            cat(&[&start]),
            echo_reads(&["FIRST", "SECOND"], Some(&answers))
        ),
    );
    harness.control.until_bound("s-1");
    harness.arm();
    harness.type_line("release");
    assert_file_stays_absent(&answers, "FIRST:", Duration::from_secs(1));
    wait_until_file_contains(&answers, "FIRST:2");
    wait_until_file_contains(&answers, "SECOND:1");
    harness.type_line("go");
}

#[test]
fn an_unarmed_pane_keeps_the_dwell_path_for_a_complete_dialog() {
    // The fast settle is delegation-only: an unarmed Pane's complete dialog
    // has no status shortcut, and nothing is ever typed or recorded.
    let dir = common::temp_dir("delegation-unarmed-settle");
    let start = start_file(&dir, "claude", "s-1");
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; {}; {}; read go",
            cat(&[&start]),
            claude_dialog("rm -rf /tmp/demo", true),
            echo_reads(&["FIRST"], Some(&answers))
        ),
    );
    harness.control.until_bound("s-1");
    holds_for(
        "an unarmed Pane was shortcut",
        Duration::from_secs(3),
        || {
            harness.control.agent()["status"] != "Permission"
                && harness.control.waiting().is_empty()
        },
    );
    harness
        .control
        .until("permission", |agent| agent["status"] == "Permission");
    assert_eq!(harness.control.waiting().len(), 1);
    assert_file_stays_absent(&answers, "FIRST:", SETTLE);
    let log = harness.events();
    assert!(decisions(&log).is_empty(), "{log:?}");
    assert_eq!(count(&log, "DelegationArmed"), 0, "{log:?}");
    harness.type_line("go");
}

#[test]
fn screen_detected_permission_is_answered_with_a_prompt_fingerprint() {
    // A screen-detected prompt has no structured payload: its record's tool
    // is "unknown" and its preview fingerprints the live prompt region, not
    // the rule-text summary every dialog of a provider shares.
    let dir = common::temp_dir("delegation-screen");
    let start = start_file(&dir, "claude", "s-1");
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; {}; {}; read go",
            cat(&[&start]),
            claude_dialog("rm -rf /tmp/demo", true),
            echo_reads(&["FIRST", "SECOND"], Some(&answers))
        ),
    );
    harness.control.until_bound("s-1");
    let agent = harness
        .control
        .until("screen permission", |agent| agent["status"] == "Permission");
    assert!(agent["details"]["pending_permission"].is_null(), "{agent}");
    let waiting = harness.control.waiting();
    assert_eq!(waiting.len(), 1, "{waiting:?}");
    let summary = waiting[0]["summary"].as_str().unwrap().to_string();
    harness.arm();
    wait_until_file_contains(&answers, "FIRST:2");
    wait_until_file_contains(&answers, "SECOND:1");
    let records = decisions(&wait_decisions(&harness.socket, |r| r.len() >= 3));
    assert_answered_then_loop(&records);
    for record in &records {
        assert_eq!(record["tool"], "unknown");
        let preview = preview(record);
        assert_ne!(preview, summary);
        assert!(
            preview.contains("Do you want to proceed?")
                && preview.contains("rm -rf /tmp/demo")
                && preview.contains("Esc to cancel"),
            "{preview}"
        );
    }
    harness.type_line("go");
}

#[test]
fn distinct_screen_dialogs_inside_the_loop_window_are_both_answered() {
    // Regression: two DIFFERENT screen dialogs share the rule-text summary,
    // so a summary-keyed identity withheld the second as a re-ask. The blank
    // screen between them idles the status, surfacing the second as a fresh
    // item.
    let dir = common::temp_dir("delegation-screen-distinct");
    let start = start_file(&dir, "claude", "s-1");
    let answers = dir.join("answers");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "stty -echo; {}; {}; {}; printf '\\033[2J\\033[H'; sleep 2; {}; {}; read go",
            cat(&[&start]),
            claude_dialog("rm -rf /tmp/demo", true),
            echo_reads(&["A1", "A2"], Some(&answers)),
            claude_dialog("ls -l /var/tmp", true),
            echo_reads(&["B1", "B2"], Some(&answers)),
        ),
    );
    harness.control.until_bound("s-1");
    harness.arm();
    let content = wait_until_file_contains(&answers, "B2:1");
    assert_eq!(
        content.lines().collect::<Vec<_>>(),
        ["A1:2", "A2:1", "B1:2", "B2:1"]
    );
    let allows = |records: &[Value]| -> Vec<Value> {
        records
            .iter()
            .filter(|record| record["verdict"]["outcome"] == "allow")
            .cloned()
            .collect()
    };
    let log = wait_decisions(&harness.socket, |r| allows(r).len() >= 4);
    let allows = allows(&decisions(&log));
    assert!(
        allows[..2]
            .iter()
            .all(|r| preview(r).contains("rm -rf /tmp/demo"))
            && allows[2..]
                .iter()
                .all(|r| preview(r).contains("ls -l /var/tmp")),
        "{allows:?}"
    );
    harness.type_line("go");
}

#[test]
fn delegation_disarms_on_invocation_change_and_pane_close() {
    let dir = common::temp_dir("delegation-lifecycle");
    let start = start_file(&dir, "claude", "s-1");
    let restart = hook_file(&dir, "restart", "claude", session_start("s-2"));
    let mut harness = harness(&dir, 30, &format!("{}; read go", cat(&[&start])));
    harness.control.until_bound("s-1");
    harness.arm();
    assert_eq!(harness.control.delegation_status().len(), 1);
    harness.type_line("go");
    wait_for("the invocation-end disarm", TIMEOUT, || {
        harness.control.delegation_status().is_empty()
    });

    // A fresh invocation can be armed again, and closing the Pane disarms it.
    thread::sleep(Duration::from_millis(200));
    harness.run("second.sh", &format!("{}; read go", cat(&[&restart])));
    harness.control.until_bound("s-2");
    harness.arm();
    // Closing the Workspace's last Pane would stop the server.
    harness.control.request(ControlCommand::PaneSplit {
        pane: uniterm_core::PaneId(harness.pane),
        axis: uniterm_proto::SplitAxis::LeftRight,
        background: true,
    });
    harness.control.request(ControlCommand::PaneClose {
        pane: uniterm_core::PaneId(harness.pane),
    });
    assert!(harness.control.delegation_status().is_empty());
    let log = harness.events();
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
    let start = start_file(&dir, "claude", "s-1");
    let mut harness = harness(&dir, 30, &format!("{}; read go", cat(&[&start])));
    harness.control.until_bound("s-1");
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(harness.pane),
        confirmed: false,
    });
    assert_eq!(frame["error"]["code"], "confirmation_required", "{frame}");
    assert!(harness.control.delegation_status().is_empty());
    let frame = harness.control.request_raw(ControlCommand::DelegationArm {
        pane: uniterm_core::PaneId(999),
        confirmed: true,
    });
    assert_eq!(frame["error"]["code"], "not_found", "{frame}");
    harness.arm();
    assert_eq!(harness.control.delegation_status().len(), 1);
    assert_eq!(count(&harness.events(), "DelegationArmed"), 1);
    harness.type_line("go");
}

#[test]
fn a_restart_never_restores_arms_or_answers() {
    let dir = common::temp_dir("delegation-restart");
    let start = start_file(&dir, "claude", "s-1");
    let ask = permission_file(&dir, "ask", "git status");
    let mut harness = harness(
        &dir,
        30,
        &format!(
            "{}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT", "FELL"], None)
        ),
    );
    harness
        .control
        .until("permission", |agent| agent["status"] == "Permission");
    harness.arm();
    harness.until_output("GOT:2");
    harness.until_output("FELL:1");
    let kill = |socket: &Path| {
        UnixStream::connect(socket)
            .unwrap()
            .write_all(&uniterm_proto::encode_frame(
                &uniterm_proto::ClientMessage::KillServer,
            ))
            .unwrap();
    };
    kill(&harness.socket);
    wait_for("the server to stop", TIMEOUT, || !harness.socket.exists());

    // The restart replays the stream: delegation events are audit-only.
    let socket = harness.socket.clone();
    let server = thread::spawn(move || {
        let _ = uniterm_server::run_server(&socket, "/bin/sh", &[]);
    });
    let mut control = Control::connect(&harness.socket);
    assert!(control.delegation_status().is_empty());
    let log = harness.events();
    assert_eq!(count(&log, "DelegationArmed"), 1);
    let before = decisions(&log).len();
    assert!(before > 0);

    // A fresh prompt on the restored Workspace just waits for the human.
    let pane = control.request(ControlCommand::PaneList)["panes"][0]["id"]
        .as_u64()
        .unwrap();
    let script = harness.files.join("second.sh");
    std::fs::write(
        &script,
        format!(
            "{}; {}; read go",
            cat(&[&start, &ask]),
            echo_reads(&["GOT2"], None)
        ),
    )
    .unwrap();
    control.type_line(pane, &format!("sh '{}'", script.display()));
    control.until("permission after restart", |agent| {
        agent["status"] == "Permission"
    });
    assert_eq!(control.waiting().len(), 1);
    control.assert_output_stays_absent(pane, "GOT2:");
    assert_eq!(decisions(&harness.events()).len(), before);
    kill(&harness.socket);
    let _ = server.join();
}

/// A Yolo Mode codex harness that draws `dialog` once the test types
/// `release`, and again a few seconds after the first answer.
fn codex_dialog_harness(dialog: &str) -> (Harness, PathBuf) {
    let dir = common::temp_dir("delegation-codex");
    let start = start_file(&dir, "codex", "c-1");
    let dialog_path = dir.join("dialog");
    std::fs::write(&dialog_path, dialog).unwrap();
    let answers = dir.join("answers");
    let draw = format!("printf '\\033[2J\\033[H'; cat '{}'", dialog_path.display());
    let mut harness = Harness::new(&dir, 30, true);
    harness.run(
        "agent.sh",
        &format!(
            "stty -echo; {}; read release; {draw}; {}; printf '\\033[2J\\033[Hran it\\n'; sleep 3; {draw}; {}; read go",
            cat(&[&start]),
            echo_reads(&["FIRST"], Some(&answers)),
            echo_reads(&["SECOND"], Some(&answers)),
        ),
    );
    harness.control.until_bound("c-1");
    (harness, answers)
}

/// The codex 0.165 approval dialog: two options, footer clipped the way a
/// short pane shows it.
const CODEX_165_DIALOG_CLIPPED: &str = "  Would you like to run the following command?\n\
\n\
  Reason: Access the already-authorized local Uniterm workspace to coordinate analysis agents.\n\
\n\
  $ ut agent list --json\n\
\n\
\u{203a} 1. Yes, proceed (y)\n\
  2. No, and tell Codex what to do differently (esc)\n";

#[test]
fn yolo_mode_answers_the_codex_165_dialog_on_the_fast_settle() {
    // Under Yolo Mode the clipped two-option dialog is answered on the fast
    // settle, and the same command asked again seconds later is answered.
    let (mut harness, answers) = codex_dialog_harness(CODEX_165_DIALOG_CLIPPED);
    harness.control.wait_armed();
    harness.type_line("release");
    let seen = harness
        .control
        .seen(harness.pane, "what to do differently (esc)");
    let content = wait_until_file_contains(&answers, "FIRST:");
    assert!(
        seen.elapsed() < Duration::from_secs(1),
        "{:?}",
        seen.elapsed()
    );
    assert_eq!(content.trim(), "FIRST:", "{content:?}");
    let content = wait_until_file_contains(&answers, "SECOND:");
    assert_eq!(content.lines().collect::<Vec<_>>(), ["FIRST:", "SECOND:"]);
    let records = decisions(&harness.events());
    assert!(outcomes(&records).iter().filter(|o| **o == "allow").count() >= 2);
    assert!(records.iter().all(|record| record["agent"] == "codex"));
    harness.type_line("go");
}
