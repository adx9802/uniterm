//! Delegated permission answering: the assistant supervisor.
//!
//! A human arms one Pane's current invocation; from then on, when that
//! invocation raises a permission waiting item the pure core evaluator
//! (`uniterm_core::evaluate_delegation`) decides whether the supervisor may
//! type the provider's own approval reply. The decision is appended to the
//! event log BEFORE any bytes are queued (the GuardrailDecision precedent),
//! the reply travels the same guarded terminal-delivery path a human answer
//! uses, and anything uncertain withholds and leaves the item to the human.
//!
//! The armed set is live-only by design: replay restores the waiting queue
//! but never the arms, so re-arming after a restart is the human's fresh
//! consent. Nothing here wakes the loop; evaluation runs only when a waiting
//! item is created or replaced, or when a human arms.

use super::*;

/// One hour, the window the answer budget resets over. The budget is a
/// counter with a lazy reset at evaluation time, never a ticker.
const BUDGET_WINDOW_MS: u64 = 3_600_000;

/// How long an identical auto-answered prompt is treated as a loop when it
/// is immediately re-asked. A re-ask means the approval did not stick, and
/// typing the same approval again would spin without a human in the loop.
const LOOP_GUARD_MS: u64 = 60_000;

/// Live arm state for one Pane, scoped to one invocation and process group.
/// Never restored from the event log.
#[derive(Clone)]
pub(super) struct DelegationState {
    /// Provider the arm validated; the approval reply is its owned data.
    agent: String,
    /// Foreground process-group identity at arm time. Answers never leak
    /// across an invocation change.
    invocation: Option<i32>,
    /// When the human armed, for audit display.
    armed_at_ms: u64,
    /// Start of the current hourly budget window.
    window_started_ms: u64,
    /// Approvals typed within the current window.
    answers_used: u16,
    /// Last (tool, preview, when) auto-answered, for the loop guard.
    last_answered: Option<(String, String, u64)>,
}

/// Remaining budget with the lazy window reset applied. A window that
/// expired resets at the next evaluation, never on a timer.
fn budget_remaining(state: &DelegationState, max: u16, now_ms: u64) -> u16 {
    if now_ms.saturating_sub(state.window_started_ms) >= BUDGET_WINDOW_MS {
        return max;
    }
    max.saturating_sub(state.answers_used)
}

/// Stable digest of the exact policy an arm consented to, so a later config
/// edit cannot quietly widen what was armed. sha2 is already a server
/// dependency for provider manifests.
fn policy_digest(policy: &uniterm_core::DelegationPolicy) -> String {
    use sha2::Digest as _;
    let mut rendered = String::new();
    for rule in &policy.allow {
        rendered.push_str(&rule.program);
        rendered.push('\u{1f}');
        if let Some(prefix) = &rule.arg_prefix {
            rendered.push_str(prefix);
        }
        rendered.push('\u{1e}');
    }
    rendered.push_str(&policy.max_answers_per_hour.to_string());
    format!("{:x}", sha2::Sha256::digest(rendered.as_bytes()))
}

impl Server {
    /// Arm delegated answering for one Pane's current invocation. The human
    /// confirmed upstream (the control `confirmed` flag or the explicit CLI
    /// verb); this validates the target, records the arm, and runs one
    /// immediate evaluation pass over an already-active waiting item.
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
        let invocation = agent.foreground_pid.or(pane_state.foreground_pid);
        let now_ms = super::guardrail::unix_time_ms();
        let policy = self.config.delegation_policy();
        // Re-arming is a fresh consent: the budget and the loop guard reset.
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
        // A prompt already on screen is the likely reason the human armed,
        // so evaluate it immediately rather than waiting for the next item.
        self.delegate_waiting_for_pane(reg, pane);
        match self.delegation_entry(pane) {
            Some(entry) => Ok(entry),
            None => Err((
                "disarmed".into(),
                "delegation disarmed itself during the first evaluation".into(),
            )),
        }
    }

    /// Stop delegated answering for one Pane, recording why. Returns whether
    /// an arm existed. Lifecycle disarms (pane close, agent exit or unbind,
    /// invocation change, budget) go through the same path so the event log
    /// always says when an approval capability ended.
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
            return (
                false,
                uniterm_core::DelegateVerdict::Withhold {
                    reason: "delegation is not armed for this pane".into(),
                },
            );
        };
        let Some(item) = self.waiting.items().iter().find(|item| item.pane == pane) else {
            return (
                true,
                uniterm_core::DelegateVerdict::Withhold {
                    reason: "no waiting item is active for this pane".into(),
                },
            );
        };
        let (verdict, _, _, _) =
            self.delegation_verdict(pane, state, item, super::guardrail::unix_time_ms());
        (true, verdict)
    }

    /// Queue one Pane for a delegation verdict. Called only from
    /// `record_waiting_change`'s Created and Replaced arms, so evaluation is
    /// damage-gated by a real queue change and costs nothing while idle.
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

    /// Drain queued delegation verdicts on the run loop's flush block, where
    /// a registry is available for the guarded terminal-delivery path.
    pub(super) fn flush_delegation(&mut self, reg: &Registry) {
        if self.pending_delegation.is_empty() {
            return;
        }
        let panes = std::mem::take(&mut self.pending_delegation);
        for pane in panes {
            self.delegate_waiting_for_pane(reg, pane);
        }
    }

    /// The verdict for one Pane's active item, computed from invocation-
    /// scoped structured facts (never the summary string) with the budget
    /// and the loop guard applied. Returns the verdict plus the tool and
    /// preview the record must carry.
    fn delegation_verdict(
        &self,
        pane: PaneId,
        state: &DelegationState,
        item: &uniterm_core::WaitingItem,
        now_ms: u64,
    ) -> (
        uniterm_core::DelegateVerdict,
        String,
        String,
        Option<&'static str>,
    ) {
        fn withhold(
            reason: impl Into<String>,
        ) -> (
            uniterm_core::DelegateVerdict,
            String,
            String,
            Option<&'static str>,
        ) {
            (
                uniterm_core::DelegateVerdict::Withhold {
                    reason: reason.into(),
                },
                String::new(),
                String::new(),
                None,
            )
        }
        let Some(pane_state) = self.panes.get(&pane) else {
            return withhold("pane no longer exists");
        };
        let Some(agent) = pane_state.agent.as_ref() else {
            return withhold("no agent is bound to the pane");
        };
        if agent.id != state.agent {
            return withhold("the bound agent changed since the arm");
        }
        let current_invocation = agent.foreground_pid.or(pane_state.foreground_pid);
        if current_invocation != state.invocation {
            return withhold("the invocation changed since the arm");
        }
        if agent.status != uniterm_core::AgentStatus::Permission {
            return withhold("the agent is no longer at a permission prompt");
        }
        if item.invocation.is_some() && item.invocation != current_invocation {
            return withhold("the waiting item belongs to an older invocation");
        }
        // Phase-0 stringly items carry no structured permission payload;
        // nothing parseable means nothing delegable.
        let Some(permission) = agent.details.pending_permission.as_ref() else {
            return withhold("the prompt arrived without structured tool and preview data");
        };
        // The loop guard runs before the budget gate: the transient re-check
        // after a delegated answer would otherwise consume a verdict slot and,
        // with the last budget unit just spent, disarm an arm that has seen no
        // genuinely new prompt.
        let policy = self.config.delegation_policy();
        if let Some((tool, preview, at_ms)) = &state.last_answered {
            if *tool == permission.tool
                && *preview == permission.preview
                && now_ms.saturating_sub(*at_ms) < LOOP_GUARD_MS
            {
                return withhold(
                    "the identical prompt was auto-answered moments ago, so this \
                                 re-ask looks like a loop",
                );
            }
        }
        if budget_remaining(state, policy.max_answers_per_hour, now_ms) == 0 {
            // The only withhold that disarms: an arm that cannot afford the
            // next answer would look live while approving nothing.
            return (
                uniterm_core::DelegateVerdict::Withhold {
                    reason: "the hourly answer budget is exhausted; re-arm to resume".into(),
                },
                permission.tool.clone(),
                permission.preview.clone(),
                Some("budget_exhausted"),
            );
        }
        let Some(project_root) = self.project_root_for_pane(pane) else {
            return withhold("the pane has no Project root to bound paths against");
        };
        let facts = uniterm_core::DelegationFacts {
            kind: item.kind,
            tool: &permission.tool,
            preview: &permission.preview,
            project_root: &project_root,
        };
        let mut verdict = uniterm_core::evaluate_delegation(&policy, &facts);
        if matches!(verdict, uniterm_core::DelegateVerdict::Allow)
            && crate::providers::approval_reply(&agent.id).is_none()
        {
            verdict = uniterm_core::DelegateVerdict::Withhold {
                reason: format!("provider {} has no verified approval reply", agent.id),
            };
        }
        (
            verdict,
            permission.tool.clone(),
            permission.preview.clone(),
            None,
        )
    }

    /// Evaluate one Pane's active waiting item and, on Allow, type the
    /// provider's approval reply. The DelegationDecision record is appended
    /// BEFORE any bytes are queued, so the audit trail exists even when
    /// typing fails. On Withhold the item stays with the human.
    fn delegate_waiting_for_pane(&mut self, reg: &Registry, pane: PaneId) {
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
        let (verdict, tool, preview, disarm_reason) =
            self.delegation_verdict(pane, &state, &item, now_ms);
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
            if let Some(reason) = disarm_reason {
                self.disarm_delegation(pane, reason);
            }
            return;
        }
        // Revalidate between the recorded decision and the side effect (the
        // waiting_action Answer precedent): the prompt must still be live
        // for the armed invocation.
        let current_invocation = self
            .panes
            .get(&pane)
            .and_then(|pane_state| pane_state.agent.as_ref())
            .and_then(|agent| agent.foreground_pid)
            .or_else(|| {
                self.panes
                    .get(&pane)
                    .and_then(|pane_state| pane_state.foreground_pid)
            });
        let still_live = self
            .panes
            .get(&pane)
            .and_then(|pane_state| pane_state.agent.as_ref())
            .is_some_and(|agent| {
                agent.id == state.agent && agent.status == uniterm_core::AgentStatus::Permission
            })
            && current_invocation == state.invocation
            && self.waiting.get(item.id).is_some();
        let Some(reply) = crate::providers::approval_reply(&state.agent) else {
            return;
        };
        if !still_live {
            return;
        }
        let accepted = if let Some(pane_state) = self.panes.get_mut(&pane) {
            let bytes = super::io::paste_input(reply, pane_state.term.bracketed_paste(), true);
            Self::queue_pane_input(reg, pane_state, &bytes)
        } else {
            false
        };
        if !accepted {
            // The input queue is full; the recorded Allow had no side effect,
            // the item stays for the human, and no budget is consumed.
            return;
        }
        if let Some(state) = self.delegated.get_mut(&pane) {
            if now_ms.saturating_sub(state.window_started_ms) >= BUDGET_WINDOW_MS {
                state.window_started_ms = now_ms;
                state.answers_used = 0;
            }
            state.answers_used = state.answers_used.saturating_add(1);
            state.last_answered = Some((tool, preview, now_ms));
        }
        self.resolve_waiting_for_pane(item.pane, uniterm_core::WaitingResolution::Answered);
        // The answer changes no status, so when a screen or title rule pins
        // the agent at permission across the approval, the repeated prompt
        // needs its own item now (the human Answer path does the same).
        self.refresh_waiting_for_pane(item.pane);
        self.arm_orchestration_deadline(item.pane);
    }

    /// One wire entry with the live (lazily reset) budget view.
    fn delegation_entry(&self, pane: PaneId) -> Option<uniterm_proto::DelegationEntry> {
        let state = self.delegated.get(&pane)?;
        let policy = self.config.delegation_policy();
        let now_ms = super::guardrail::unix_time_ms();
        let used = if now_ms.saturating_sub(state.window_started_ms) >= BUDGET_WINDOW_MS {
            0
        } else {
            state.answers_used
        };
        Some(uniterm_proto::DelegationEntry {
            pane,
            agent: state.agent.clone(),
            invocation: state.invocation,
            armed_at_ms: state.armed_at_ms,
            answers_used: used,
            answers_remaining: policy.max_answers_per_hour.saturating_sub(used),
        })
    }
}
