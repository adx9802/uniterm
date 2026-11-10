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
//! Arms are live-only: replay restores the waiting queue but never the arms.
//! Evaluation runs only when a waiting item is created or replaced, or when a
//! Pane is armed.

use super::*;

/// The window the answer budget resets over, lazily at evaluation time.
const BUDGET_WINDOW_MS: u64 = 3_600_000;

/// How long an identical prompt re-asked after a plain yes counts as a loop:
/// the approval did not stick, and typing it again would spin.
const LOOP_GUARD_MS: u64 = 60_000;

/// Rows of the prompt region a screen-detected prompt fingerprints: the same
/// region the provider screen rules scan, read once per verdict.
const PROMPT_REGION_LINES: usize = 12;

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
fn reask_is_loop(last: &LastAnswer, tool: &str, preview: &str, now_ms: u64) -> bool {
    !last.used_always && last.reasked_by(tool, preview, now_ms)
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
        self.delegate_waiting(reg, pane);
        self.delegation_entry(pane).ok_or_else(|| {
            (
                "disarmed".into(),
                "delegation disarmed itself during the first evaluation".into(),
            )
        })
    }

    /// Stop delegated answering for one Pane, recording why. Returns whether
    /// an arm existed.
    pub(super) fn disarm_delegation(&mut self, pane: PaneId, reason: &str) -> bool {
        let Some(state) = self.delegated.remove(&pane) else {
            return false;
        };
        self.pending_delegation.retain(|pending| *pending != pane);
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
        (true, self.evaluate(pane, state, item, now_ms).verdict)
    }

    /// Queue one Pane for a verdict. Called only when a waiting item is
    /// created or replaced, so evaluation costs nothing while idle.
    pub(super) fn maybe_delegate_waiting(&mut self, item: &uniterm_core::WaitingItem) {
        if item.kind != uniterm_core::WaitingKind::Permission {
            return;
        }
        if !self.delegated.contains_key(&item.pane) {
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
            self.delegate_waiting(reg, pane);
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

    /// The verdict for one Pane's active item: invocation scoping, the loop
    /// guard and the budget around the pure core kind gate.
    fn evaluate(
        &self,
        pane: PaneId,
        state: &DelegationState,
        item: &uniterm_core::WaitingItem,
        now_ms: u64,
    ) -> Evaluation {
        let (pane_state, agent) = match self.armed_agent(pane, state) {
            Ok(bound) => bound,
            Err(reason) => return Evaluation::withheld(reason),
        };
        if agent.status != uniterm_core::AgentStatus::Permission {
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
        if state
            .last_answered
            .as_ref()
            .is_some_and(|last| reask_is_loop(last, &tool, &preview, now_ms))
        {
            return identified(
                withhold(
                    "the identical prompt was auto-answered moments ago, so this re-ask looks like a loop",
                ),
                None,
            );
        }
        let max = self.config.delegation_policy().max_answers_per_hour;
        if state.answers_used_at(now_ms) >= max {
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
    fn delegate_waiting(&mut self, reg: &Registry, pane: PaneId) {
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
        } = self.evaluate(pane, &state, &item, now_ms);
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
            .is_ok_and(|(_, agent)| agent.status == uniterm_core::AgentStatus::Permission);
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
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_loop_guard_withholds_a_reask_after_a_plain_yes() {
        let preview = "$ ut agent list --json";
        let answered = |used_always| LastAnswer {
            tool: "unknown".into(),
            preview: preview.into(),
            at_ms: 1_000,
            used_always,
        };
        let is_loop = |last: &LastAnswer, preview: &str, at: u64| {
            reask_is_loop(last, "unknown", preview, 1_000 + at)
        };
        let plain = answered(false);
        assert!(is_loop(&plain, preview, 10));
        assert!(is_loop(&plain, preview, LOOP_GUARD_MS - 1));
        assert!(!is_loop(&plain, preview, LOOP_GUARD_MS));
        // A distinct prompt and the always-to-yes escalation never loop.
        assert!(!is_loop(&plain, "$ git status", 10));
        assert!(!is_loop(&answered(true), preview, 10));
    }
}
