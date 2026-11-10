//! Delegated permission answering: the assistant supervisor.
//!
//! A human arms one Pane's current invocation; from then on, when that
//! invocation raises a permission waiting item the pure core evaluator
//! (`uniterm_core::evaluate_delegation`) allows it and the supervisor types
//! the provider's approval reply through the same guarded terminal-delivery
//! path a human answer uses. Every decision is appended to the event log
//! BEFORE any bytes are queued. Questions always stay with the human.
//!
//! The first answer to a prompt prefers the provider's always-reply (its
//! "don't ask again" option); when the same prompt re-surfaces, the plain
//! yes-reply answers it. One verdict types at most one reply.
//!
//! Three rails bound the blast radius: the kind gate (questions are never
//! delegated), the hourly answer budget (a spent arm disarms itself), and the
//! loop guard (an identical prompt that comes straight back after a plain yes
//! is withheld). Prompts are identified by their structured tool+preview, or
//! for screen-detected prompts by a fingerprint of the live prompt region,
//! because the matched rule text is the same for every dialog of a provider.
//!
//! Yolo Mode (`delegation-auto-arm`) is standing consent: every live
//! supported Pane is kept armed, there is no budget, and the loop guard only
//! catches the re-check before the keystroke landed and a dialog that keeps
//! cycling. An explicit human disarm still holds for that invocation.
//!
//! Arms are live-only: replay restores the waiting queue but never the arms.
//! Evaluation runs only when a waiting item is created or replaced, when a
//! Pane is armed, or when an armed Pane's fast settle fires.
//!
//! The fast settle skips the generic permission dwell for an ARMED Pane: when
//! its dialog region shows the provider's COMPLETE dialog signature
//! (question, options, footer) and stays byte-stable for `DELEGATION_SETTLE`,
//! the verdict runs with that signature standing in for the smoothed
//! permission status. The settle tick is one-shot and damage-gated; a partial
//! dialog never completes the signature, and a withhold leaves the normal
//! dwell path untouched.

use super::*;

/// The window the answer budget resets over, lazily at evaluation time.
const BUDGET_WINDOW_MS: u64 = 3_600_000;

/// How long an identical prompt re-asked after a plain yes counts as a loop:
/// the approval did not stick, and typing it again would spin.
const LOOP_GUARD_MS: u64 = 60_000;

/// Under Yolo Mode, how soon after an answer an identical prompt is still the
/// same dialog waiting for the keystroke to land.
const YOLO_REASK_SETTLE_MS: u64 = 2_000;

/// Under Yolo Mode, how many consecutive identical answers inside the loop
/// window are allowed before the dialog goes to the human.
const YOLO_MAX_IDENTICAL_REPEATS: u16 = 10;

/// Rows of the prompt region a screen-detected prompt fingerprints: the same
/// region the provider screen rules scan, read once per verdict.
const PROMPT_REGION_LINES: usize = 12;

/// Rows the fast settle scans for the complete dialog signature. Taller than
/// the status region because the anchored question line is the top of the
/// dialog: a long-command codex approval repeats the command in its
/// don't-ask-again option and measures about 28 rows. A dialog taller than
/// the grid or this bound never completes and keeps the dwell fail-safe.
pub(super) const DIALOG_REGION_LINES: usize = 48;

/// How long an armed Pane's complete dialog must stay byte-stable before the
/// fast settle evaluates it: long enough to outlast a multi-frame paint
/// burst, short enough to answer about 0.1 s after the dialog completes.
pub(super) const DELEGATION_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

/// Arm, re-arm, or clear one Pane's fast-settle deadline after its evidence
/// region changed. The deadline fires only after an uninterrupted quiet
/// settle with the complete signature on screen.
pub(super) fn track_delegation_settle(pane: &mut Pane, armed: bool, tail: &str) {
    let complete = armed
        && pane
            .agent
            .as_ref()
            .is_some_and(|agent| crate::providers::complete_permission_dialog(&agent.id, tail));
    if !complete {
        pane.delegation_settle = None;
        return;
    }
    let hash = super::agents::evidence_hash(tail);
    if pane.delegation_settle.map(|(_, armed_hash)| armed_hash) != Some(hash) {
        pane.delegation_settle = Some((std::time::Instant::now() + DELEGATION_SETTLE, hash));
    }
}

/// The foreground process group a Pane's arm is scoped to.
fn invocation_of(pane: &Pane) -> Option<i32> {
    pane.agent
        .as_ref()
        .and_then(|agent| agent.foreground_pid)
        .or(pane.foreground_pid)
}

/// Live arm state for one Pane, scoped to one invocation. Never restored from
/// the event log.
#[derive(Clone)]
pub(super) struct DelegationState {
    /// Provider the arm validated; the approval reply is its owned data.
    agent: String,
    invocation: Option<i32>,
    armed_at_ms: u64,
    window_started_ms: u64,
    /// Approvals typed within the current budget window.
    answers_used: u16,
    last_answered: Option<LastAnswer>,
}

impl DelegationState {
    fn window_expired(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.window_started_ms) >= BUDGET_WINDOW_MS
    }

    /// Answers spent in the current window, with the lazy reset applied.
    fn answers_used_at(&self, now_ms: u64) -> u16 {
        if self.window_expired(now_ms) {
            0
        } else {
            self.answers_used
        }
    }
}

/// The last prompt one arm answered, keyed by its (tool, preview) identity.
#[derive(Clone)]
struct LastAnswer {
    tool: String,
    preview: String,
    at_ms: u64,
    used_always: bool,
    /// Consecutive identical answers, each inside the loop window of the
    /// previous one.
    repeats: u16,
}

impl LastAnswer {
    /// Whether `tool`/`preview` re-asks this prompt inside the loop window.
    fn reasked_by(&self, tool: &str, preview: &str, now_ms: u64) -> bool {
        self.tool == tool
            && self.preview == preview
            && now_ms.saturating_sub(self.at_ms) < LOOP_GUARD_MS
    }
}

/// Whether an identical prompt re-asked after `last` is a loop. The
/// resurface after an always-reply is owed one plain yes, so it never loops.
fn reask_is_loop(last: &LastAnswer, tool: &str, preview: &str, now_ms: u64, yolo: bool) -> bool {
    if last.used_always || !last.reasked_by(tool, preview, now_ms) {
        return false;
    }
    !yolo
        || now_ms.saturating_sub(last.at_ms) < YOLO_REASK_SETTLE_MS
        || last.repeats >= YOLO_MAX_IDENTICAL_REPEATS
}

/// Stable digest of the policy an arm consented to, so a later config edit
/// cannot quietly widen what was armed.
fn policy_digest(policy: &uniterm_core::DelegationPolicy) -> String {
    use sha2::Digest as _;
    format!(
        "{:x}",
        sha2::Sha256::digest(policy.max_answers_per_hour.to_string().as_bytes())
    )
}

fn withhold(reason: impl Into<String>) -> uniterm_core::DelegateVerdict {
    uniterm_core::DelegateVerdict::Withhold {
        reason: reason.into(),
    }
}

/// One verdict with the prompt identity its record carries, and the disarm
/// reason for the one withhold that disarms.
struct Evaluation {
    verdict: uniterm_core::DelegateVerdict,
    tool: String,
    preview: String,
    disarm: Option<&'static str>,
}

impl Evaluation {
    fn withheld(reason: impl Into<String>) -> Self {
        Evaluation {
            verdict: withhold(reason),
            tool: String::new(),
            preview: String::new(),
            disarm: None,
        }
    }
}

impl Server {
    /// Arm delegated answering for one Pane's current invocation. The human
    /// confirmed upstream (the control `confirmed` flag or the CLI verb).
    pub(super) fn arm_delegation(
        &mut self,
        reg: &Registry,
        pane: PaneId,
    ) -> Result<uniterm_proto::DelegationEntry, (String, String)> {
        let Some(pane_state) = self.panes.get(&pane) else {
            return Err((
                "not_found".into(),
                "Pane not found in this Workspace".into(),
            ));
        };
        let Some(agent) = pane_state.agent.as_ref() else {
            return Err(("no_agent".into(), "no agent is bound to the pane".into()));
        };
        if crate::providers::approval_reply(&agent.id).is_none() {
            return Err((
                "unsupported_provider".into(),
                format!(
                    "{} has no verified approval reply, so delegation stays off",
                    agent.id
                ),
            ));
        }
        let invocation = invocation_of(pane_state);
        let now_ms = super::guardrail::unix_time_ms();
        let policy = self.config.delegation_policy();
        self.delegation_opt_out.remove(&pane);
        // Re-arming is fresh consent: the budget and the always/yes memory
        // reset.
        self.delegated.insert(
            pane,
            DelegationState {
                agent: agent.id.clone(),
                invocation,
                armed_at_ms: now_ms,
                window_started_ms: now_ms,
                answers_used: 0,
                last_answered: None,
            },
        );
        self.append_event(crate::eventlog::LogEvent::DelegationArmed {
            pane,
            invocation,
            policy_digest: policy_digest(&policy),
        });
        // A prompt already on screen is the likely reason the human armed.
        self.delegate_waiting(reg, pane, false);
        if self.delegated.contains_key(&pane) {
            if let Some(pane_state) = self.panes.get_mut(&pane) {
                let tail = pane_state.term.evidence_text(DIALOG_REGION_LINES);
                track_delegation_settle(pane_state, true, &tail);
            }
        }
        self.delegation_entry(pane).ok_or_else(|| {
            (
                "disarmed".into(),
                "delegation disarmed itself during the first evaluation".into(),
            )
        })
    }

    /// Keep one Pane armed while Yolo Mode is on. Runs when an invocation
    /// binds, when the switch flips on, and when an unarmed Pane raises a
    /// permission prompt. Unsupported providers are skipped silently, and an
    /// invocation the human explicitly disarmed stays disarmed.
    pub(super) fn maybe_auto_arm_delegation(&mut self, reg: &Registry, pane: PaneId) {
        if !self.config.delegation_auto_arm {
            return;
        }
        let Some(pane_state) = self.panes.get(&pane) else {
            return;
        };
        let Some(agent) = pane_state.agent.as_ref() else {
            return;
        };
        if crate::providers::approval_reply(&agent.id).is_none() {
            return;
        }
        let invocation = invocation_of(pane_state);
        if let Some(state) = self.delegated.get(&pane) {
            if state.agent == agent.id && state.invocation == invocation {
                return;
            }
            self.disarm_delegation(pane, "invocation_changed");
        }
        if self.delegation_opt_out.get(&pane) == Some(&invocation) {
            return;
        }
        // A refusal only means the target went away since the trigger.
        let _ = self.arm_delegation(reg, pane);
    }

    /// Arm every live supported Pane, in Pane order, when Yolo Mode flips on.
    pub(super) fn auto_arm_all_delegations(&mut self, reg: &Registry) {
        let mut panes: Vec<PaneId> = self
            .panes
            .iter()
            .filter(|(_, pane)| pane.agent.is_some())
            .map(|(id, _)| *id)
            .collect();
        panes.sort_by_key(|pane| pane.0);
        for pane in panes {
            self.maybe_auto_arm_delegation(reg, pane);
        }
    }

    /// Stop delegated answering for one Pane, recording why. Returns whether
    /// an arm existed. `"disarmed"` is the explicit human disarm, which
    /// outranks Yolo Mode for the rest of the invocation; every other reason
    /// ends the invocation and with it that opt-out.
    pub(super) fn disarm_delegation(&mut self, pane: PaneId, reason: &str) -> bool {
        let explicit = reason == "disarmed";
        if !explicit {
            self.delegation_opt_out.remove(&pane);
        }
        let Some(state) = self.delegated.remove(&pane) else {
            return false;
        };
        if explicit {
            self.delegation_opt_out.insert(pane, state.invocation);
        }
        self.pending_delegation.retain(|pending| *pending != pane);
        if let Some(pane_state) = self.panes.get_mut(&pane) {
            pane_state.delegation_settle = None;
        }
        self.append_event(crate::eventlog::LogEvent::DelegationDisarmed {
            pane,
            invocation: state.invocation,
            reason: reason.to_string(),
        });
        true
    }

    /// Armed delegations, optionally scoped to one Pane, with live budget use.
    pub(super) fn delegation_entries(
        &self,
        pane: Option<PaneId>,
    ) -> Vec<uniterm_proto::DelegationEntry> {
        let mut entries: Vec<_> = self
            .delegated
            .keys()
            .filter(|key| pane.is_none_or(|pane| **key == pane))
            .filter_map(|key| self.delegation_entry(*key))
            .collect();
        entries.sort_by_key(|entry| entry.pane.0);
        entries
    }

    /// The verdict the delegate would reach for one Pane's active waiting
    /// item right now, without recording or typing anything. `found` is
    /// whether the Pane is armed at all.
    pub(super) fn explain_delegation(&self, pane: PaneId) -> (bool, uniterm_core::DelegateVerdict) {
        let Some(state) = self.delegated.get(&pane) else {
            return (false, withhold("delegation is not armed for this pane"));
        };
        let Some(item) = self.waiting.items().iter().find(|item| item.pane == pane) else {
            return (true, withhold("no waiting item is active for this pane"));
        };
        let now_ms = super::guardrail::unix_time_ms();
        (
            true,
            self.evaluate(pane, state, item, now_ms, false).verdict,
        )
    }

    /// Queue one Pane for a verdict. Called only when a waiting item is
    /// created or replaced, so evaluation costs nothing while idle.
    pub(super) fn maybe_delegate_waiting(&mut self, item: &uniterm_core::WaitingItem) {
        if item.kind != uniterm_core::WaitingKind::Permission {
            return;
        }
        // Under Yolo Mode an unarmed Pane is queued too: the flush arms it.
        if !self.delegated.contains_key(&item.pane) && !self.config.delegation_auto_arm {
            return;
        }
        if !self.pending_delegation.contains(&item.pane) {
            self.pending_delegation.push(item.pane);
        }
    }

    /// Drain queued verdicts on the run loop's flush block, where a registry
    /// is available for terminal delivery.
    pub(super) fn flush_delegation(&mut self, reg: &Registry) {
        for pane in std::mem::take(&mut self.pending_delegation) {
            if self.delegated.contains_key(&pane) {
                self.delegate_waiting(reg, pane, false);
            } else {
                self.maybe_auto_arm_delegation(reg, pane);
            }
        }
    }

    /// Fire every due fast-settle deadline. Each Pane is re-verified from
    /// scratch before anything is evaluated, so a stale deadline never
    /// answers a moved dialog.
    pub(super) fn flush_delegation_settles(&mut self, reg: &Registry) {
        let now = std::time::Instant::now();
        let due: Vec<PaneId> = self
            .panes
            .iter_mut()
            .filter(|(_, pane)| {
                pane.delegation_settle
                    .is_some_and(|(deadline, _)| now >= deadline)
            })
            .map(|(id, pane)| {
                pane.delegation_settle = None;
                *id
            })
            .collect();
        for pane in due {
            self.delegate_settled_dialog(reg, pane);
        }
    }

    /// The Pane and agent an arm still applies to: the same provider and the
    /// same invocation it was armed for.
    fn armed_agent(
        &self,
        pane: PaneId,
        state: &DelegationState,
    ) -> Result<(&Pane, &PaneAgent), &'static str> {
        let pane_state = self.panes.get(&pane).ok_or("pane no longer exists")?;
        let agent = pane_state
            .agent
            .as_ref()
            .ok_or("no agent is bound to the pane")?;
        if agent.id != state.agent {
            return Err("the bound agent changed since the arm");
        }
        if invocation_of(pane_state) != state.invocation {
            return Err("the invocation changed since the arm");
        }
        Ok((pane_state, agent))
    }

    /// Answer an armed Pane's settled permission dialog without waiting for
    /// the permission dwell. The smoothed status is untouched, so a withhold
    /// leaves the dwell path to surface the item exactly as before.
    fn delegate_settled_dialog(&mut self, reg: &Registry, pane: PaneId) {
        let Some(state) = self.delegated.get(&pane) else {
            return;
        };
        let Ok((pane_state, agent)) = self.armed_agent(pane, state) else {
            return;
        };
        // Stray keystrokes must never land in an input box: re-verify the
        // complete signature against the live screen.
        let tail = pane_state.term.evidence_text(DIALOG_REGION_LINES);
        if !crate::providers::complete_permission_dialog(&agent.id, &tail) {
            return;
        }
        // Once the Pane has a waiting item the dwell path owns it.
        if self.waiting.items().iter().any(|item| item.pane == pane) {
            return;
        }
        // Shaped like the item the permission dwell would create, so the
        // audit trail reads the same on either path.
        let summary = format!(
            "{} is waiting for permission",
            uniterm_core::agent::agent_name(&agent.id)
        );
        let invocation = state.invocation;
        let change = self.waiting.request(
            pane,
            invocation,
            uniterm_core::WaitingKind::Permission,
            &summary,
        );
        self.record_waiting_change(change);
        // This verdict IS the item's delegation pass.
        self.pending_delegation.retain(|pending| *pending != pane);
        self.delegate_waiting(reg, pane, true);
    }

    /// The verdict for one Pane's active item: invocation scoping, the loop
    /// guard and the budget around the pure core kind gate.
    /// `settled_screen` is the fast settle's proof that the complete dialog
    /// stood quiet on screen, standing in for the permission status.
    fn evaluate(
        &self,
        pane: PaneId,
        state: &DelegationState,
        item: &uniterm_core::WaitingItem,
        now_ms: u64,
        settled_screen: bool,
    ) -> Evaluation {
        let (pane_state, agent) = match self.armed_agent(pane, state) {
            Ok(bound) => bound,
            Err(reason) => return Evaluation::withheld(reason),
        };
        if agent.status != uniterm_core::AgentStatus::Permission && !settled_screen {
            return Evaluation::withheld("the agent is no longer at a permission prompt");
        }
        if item.invocation.is_some() && item.invocation != state.invocation {
            return Evaluation::withheld("the waiting item belongs to an older invocation");
        }
        let (tool, preview) = match agent.details.pending_permission.as_ref() {
            Some(permission) => (permission.tool.clone(), permission.preview.clone()),
            None => {
                let fingerprint = uniterm_core::agent_detail::fingerprint_text(
                    &pane_state.term.evidence_text(PROMPT_REGION_LINES),
                    uniterm_core::agent_detail::DETAIL_TEXT_LIMIT,
                );
                if fingerprint.is_empty() {
                    // A permission pin with a blank prompt region is stale
                    // evidence: never type into a screen that cannot be
                    // identified.
                    return Evaluation {
                        tool: "unknown".into(),
                        preview: uniterm_core::agent_detail::bounded_text(
                            &item.summary,
                            uniterm_core::agent_detail::DETAIL_TEXT_LIMIT,
                        ),
                        ..Evaluation::withheld(
                            "the prompt region is blank, so there is no live dialog to identify",
                        )
                    };
                }
                ("unknown".to_string(), fingerprint)
            }
        };
        let identified = |verdict, disarm| Evaluation {
            verdict,
            tool: tool.clone(),
            preview: preview.clone(),
            disarm,
        };
        // The loop guard runs before the budget gate, so the transient
        // re-check after an answer cannot spend the last unit and disarm.
        let yolo = self.config.delegation_auto_arm;
        if state
            .last_answered
            .as_ref()
            .is_some_and(|last| reask_is_loop(last, &tool, &preview, now_ms, yolo))
        {
            return identified(
                withhold(
                    "the identical prompt was auto-answered moments ago, so this re-ask looks like a loop",
                ),
                None,
            );
        }
        let max = self.config.delegation_policy().max_answers_per_hour;
        if !yolo && state.answers_used_at(now_ms) >= max {
            // The only withhold that disarms: a spent arm would look live
            // while approving nothing.
            return identified(
                withhold("the hourly answer budget is exhausted; re-arm to resume"),
                Some("budget_exhausted"),
            );
        }
        let mut verdict = uniterm_core::evaluate_delegation(item.kind);
        if matches!(verdict, uniterm_core::DelegateVerdict::Allow)
            && crate::providers::approval_reply(&agent.id).is_none()
        {
            verdict = withhold(format!(
                "provider {} has no verified approval reply",
                agent.id
            ));
        }
        identified(verdict, None)
    }

    /// Evaluate one Pane's active waiting item and, on Allow, type the
    /// provider's approval reply. The decision is recorded BEFORE any bytes
    /// are queued; on Withhold the item stays with the human.
    fn delegate_waiting(&mut self, reg: &Registry, pane: PaneId, settled_screen: bool) {
        let Some(state) = self.delegated.get(&pane).cloned() else {
            return;
        };
        let Some(item) = self
            .waiting
            .items()
            .iter()
            .find(|item| item.pane == pane)
            .cloned()
        else {
            return;
        };
        let now_ms = super::guardrail::unix_time_ms();
        let Evaluation {
            verdict,
            tool,
            preview,
            disarm,
        } = self.evaluate(pane, &state, &item, now_ms, settled_screen);
        let allow = matches!(verdict, uniterm_core::DelegateVerdict::Allow);
        self.append_event(crate::eventlog::LogEvent::DelegationDecision {
            record: uniterm_core::DelegationRecord {
                pane,
                waiting_id: item.id,
                invocation: state.invocation,
                agent: state.agent.clone(),
                tool: tool.clone(),
                preview: preview.clone(),
                verdict,
            },
        });
        if !allow {
            if let Some(reason) = disarm {
                self.disarm_delegation(pane, reason);
            }
            return;
        }
        // Revalidate between the recorded decision and the side effect: the
        // prompt must still be live for the armed invocation.
        let prompt_live = self
            .armed_agent(pane, &state)
            .is_ok_and(|(pane_state, agent)| {
                agent.status == uniterm_core::AgentStatus::Permission
                    || (settled_screen
                        && crate::providers::complete_permission_dialog(
                            &agent.id,
                            &pane_state.term.evidence_text(DIALOG_REGION_LINES),
                        ))
            });
        if !prompt_live || self.waiting.get(item.id).is_none() {
            return;
        }
        let Some(yes_reply) = crate::providers::approval_reply(&state.agent) else {
            return;
        };
        // A re-ask of the last answered prompt means the always keystroke
        // did not stick for this variant, so it gets the plain yes.
        let reask = state
            .last_answered
            .as_ref()
            .filter(|last| last.reasked_by(&tool, &preview, now_ms));
        let repeats = reask.map_or(1, |last| last.repeats.saturating_add(1));
        let always_reply = crate::providers::always_reply(&state.agent).filter(|_| reask.is_none());
        let reply = always_reply.unwrap_or(yes_reply);
        let accepted = self.panes.get_mut(&pane).is_some_and(|pane_state| {
            let bytes = super::io::paste_input(reply, pane_state.term.bracketed_paste(), true);
            Self::queue_pane_input(reg, pane_state, &bytes)
        });
        if !accepted {
            // The input queue is full: no side effect, no budget spent.
            return;
        }
        if let Some(state) = self.delegated.get_mut(&pane) {
            if state.window_expired(now_ms) {
                state.window_started_ms = now_ms;
                state.answers_used = 0;
            }
            state.answers_used = state.answers_used.saturating_add(1);
            state.last_answered = Some(LastAnswer {
                tool,
                preview,
                at_ms: now_ms,
                used_always: always_reply.is_some(),
                repeats,
            });
        }
        self.resolve_waiting_for_pane(item.pane, uniterm_core::WaitingResolution::Answered);
        // A screen or title rule can pin the agent at permission across the
        // approval, so the repeated prompt needs its own item now.
        self.refresh_waiting_for_pane(item.pane);
        self.arm_orchestration_deadline(item.pane);
    }

    /// One wire entry with the live (lazily reset) budget view.
    fn delegation_entry(&self, pane: PaneId) -> Option<uniterm_proto::DelegationEntry> {
        let state = self.delegated.get(&pane)?;
        let used = state.answers_used_at(super::guardrail::unix_time_ms());
        Some(uniterm_proto::DelegationEntry {
            pane,
            agent: state.agent.clone(),
            invocation: state.invocation,
            armed_at_ms: state.armed_at_ms,
            answers_used: used,
            answers_remaining: self
                .config
                .delegation_policy()
                .max_answers_per_hour
                .saturating_sub(used),
            unlimited: self.config.delegation_auto_arm,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fast-settle dialog region of a 120x30 grid showing `screen`.
    fn dialog_region(screen: &str) -> String {
        let mut term = crate::terminal::Terminal::new(120, 30);
        term.feed(format!("\u{1b}[2J\u{1b}[H{screen}").as_bytes());
        term.evidence_text(DIALOG_REGION_LINES)
    }

    /// A codex approval dialog with `padding` wrapped command rows, how real
    /// long-command approvals grow. Lines carry their own carriage returns,
    /// which a PTY would add on the way to the grid.
    fn tall_dialog(padding: usize, complete: bool) -> String {
        let mut dialog = String::from("  Would you like to run the following command?\r\n\r\n");
        for line in 0..padding {
            dialog.push_str(&format!("  $ git add --verbose-path-{line:02}.rs \\\r\n"));
        }
        dialog.push_str("\u{203a} 1. Yes, proceed (y)\r\n");
        if complete {
            dialog.push_str(
                "  2. No, and tell Codex what to do differently (esc)\r\n\r\n  Press enter to confirm or esc to cancel\r\n",
            );
        }
        dialog
    }

    #[test]
    fn the_dialog_region_completes_only_whole_dialogs_on_the_grid() {
        let complete = |screen: &str| {
            crate::providers::complete_permission_dialog("codex", &dialog_region(screen))
        };
        // 28 rows on a 30-row grid: a real long-command approval.
        assert!(complete(&tall_dialog(22, true)));
        // 46 rows: the question line scrolled off, so the dwell owns it.
        assert!(!complete(&tall_dialog(40, true)));
        // Still painting its options: height never substitutes for them.
        assert!(!complete(&tall_dialog(22, false)));
        // Codex 0.165's two-option dialog with the footer clipped.
        assert!(complete(
            "  Would you like to run the following command?\r\n\r\n  $ ut agent list --json\r\n\r\n\u{203a} 1. Yes, proceed (y)\r\n  2. No, and tell Codex what to do differently (esc)\r\n"
        ));
    }

    #[test]
    fn the_loop_guard_catches_reasks_but_answers_reruns_under_yolo_mode() {
        let preview = "$ ut agent list --json";
        let answered = |used_always, repeats| LastAnswer {
            tool: "unknown".into(),
            preview: preview.into(),
            at_ms: 1_000,
            used_always,
            repeats,
        };
        let is_loop = |last: &LastAnswer, preview: &str, at: u64, yolo: bool| {
            reask_is_loop(last, "unknown", preview, 1_000 + at, yolo)
        };
        let plain = answered(false, 1);
        // Without Yolo Mode any identical re-ask inside the window loops.
        assert!(is_loop(&plain, preview, 10, false));
        assert!(is_loop(&plain, preview, LOOP_GUARD_MS - 1, false));
        assert!(!is_loop(&plain, preview, LOOP_GUARD_MS, false));
        // Under Yolo Mode only the re-check before the keystroke landed...
        assert!(is_loop(&plain, preview, YOLO_REASK_SETTLE_MS - 1, true));
        assert!(!is_loop(&plain, preview, YOLO_REASK_SETTLE_MS, true));
        // ...and a dialog that keeps cycling identically loop.
        let cycling = answered(false, YOLO_MAX_IDENTICAL_REPEATS);
        assert!(is_loop(&cycling, preview, YOLO_REASK_SETTLE_MS, true));
        assert!(!is_loop(&cycling, preview, LOOP_GUARD_MS, true));
        // A distinct prompt and the always-to-yes escalation never loop.
        for yolo in [false, true] {
            assert!(!is_loop(&plain, "$ git status", 10, yolo));
            assert!(!is_loop(&answered(true, 1), preview, 10, yolo));
        }
    }
}
