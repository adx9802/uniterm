//! Delegated permission answering: the assistant supervisor.
//!
//! A human arms one Pane's current invocation; from then on, when that
//! invocation raises a permission waiting item the pure core evaluator
//! (`uniterm_core::evaluate_delegation`) allows it and the supervisor types
//! the provider's approval reply. The decision is appended to the event log
//! BEFORE any bytes are queued (the GuardrailDecision precedent), and the
//! reply travels the same guarded terminal-delivery path a human answer
//! uses. Questions always withhold and stay with the human; permission
//! prompts are answered whether they arrived as structured (OSC 777) tool
//! data or as a screen-detected (Phase-0 stringly) prompt.
//!
//! The reply is provider-owned data: the first answer to a prompt prefers
//! the provider's verified always-reply (its "don't ask again" option), and
//! when the same prompt re-surfaces the plain yes-reply answers it from then
//! on. One verdict types at most one reply, so the two keystrokes never go
//! back to back into a live prompt.
//!
//! Three rails bound the blast radius: the pure kind gate (questions are
//! never delegated), the hourly answer budget (an arm that spends it
//! disarms itself until the human re-arms), and the identical-re-ask loop
//! guard, which withholds a prompt that comes straight back after being
//! plainly approved - but never blocks the always-to-yes escalation. The
//! identity the guard and the always/yes memory key on is the structured
//! tool+preview for OSC 777 prompts, and for screen-detected prompts a
//! bounded fingerprint of the live prompt region captured at verdict time:
//! the matched rule text is identical for every dialog one provider raises,
//! so only the prompt content can tell two dialogs apart.
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
/// is immediately re-asked. A re-ask after a plain yes means the approval
/// did not stick, and typing the same approval again would spin without a
/// human in the loop.
const LOOP_GUARD_MS: u64 = 60_000;

/// Rows of the prompt region a screen-detected prompt fingerprints: the
/// same cursor-to-bottom region the provider screen rules scan
/// (`Terminal::evidence_text`), read once per verdict, never per frame, so
/// the hot path stays damage-gated. The fingerprint only identifies one
/// dialog from another, and the actionable rows (command, options, footer)
/// sit at the very bottom, so it keeps the status region's bound.
const PROMPT_REGION_LINES: usize = 12;

/// The loop-guard identity and audit preview for a screen-detected
/// (Phase-0 stringly) prompt: a bounded, normalized fingerprint of the
/// pane's live prompt region. Distinct dialogs get distinct identities; a
/// genuinely re-asked identical dialog keeps its own, so the loop guard
/// still catches real loops. Empty when the region shows no prompt content.
fn prompt_region_fingerprint(pane: &Pane) -> String {
    uniterm_core::agent_detail::fingerprint_text(
        &pane.term.evidence_text(PROMPT_REGION_LINES),
        uniterm_core::agent_detail::DETAIL_TEXT_LIMIT,
    )
}

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
    /// The last answered prompt: its (tool, preview) identity, when, and
    /// whether the provider's always-reply was typed. A first sighting gets
    /// the always-reply; a re-surfaced prompt gets the plain yes-reply
    /// once; an identical re-ask after that yes is the loop the guard
    /// withholds.
    last_answered: Option<(String, String, u64, bool)>,
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
    format!(
        "{:x}",
        sha2::Sha256::digest(policy.max_answers_per_hour.to_string().as_bytes())
    )
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
        // Re-arming is a fresh consent: the budget, the answer counter, and
        // the always/yes memory reset.
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

    /// Arm a freshly bound invocation when `delegation-auto-arm` is on. The
    /// config key IS the human's standing consent for this path, so the
    /// control `confirmed` flag does not apply here; the arm goes through
    /// the same internal path as `arm_delegation` (same `DelegationArmed`
    /// event, same immediate evaluation pass over an active waiting item).
    /// Providers without a verified approval reply are skipped silently:
    /// arming was never possible for them, so an event would be spam, not a
    /// decision. This runs only when a genuinely new invocation binds, never
    /// from a verdict, so an arm is never quietly re-created underneath the
    /// human within one invocation - and a `budget_exhausted` disarm in
    /// particular is never auto-re-armed: spending the budget hands the
    /// prompts back until the human re-arms or a new invocation binds.
    pub(super) fn maybe_auto_arm_delegation(&mut self, reg: &Registry, pane: PaneId) {
        if !self.config.delegation_auto_arm {
            return;
        }
        let supported = self
            .panes
            .get(&pane)
            .and_then(|pane_state| pane_state.agent.as_ref())
            .is_some_and(|agent| crate::providers::approval_reply(&agent.id).is_some());
        if !supported {
            return;
        }
        // A refusal only means the target went away between the binding and
        // now; the next binding is a fresh chance to arm.
        let _ = self.arm_delegation(reg, pane);
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

    /// Armed delegations, optionally scoped to one Pane, with live budget
    /// use.
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

    /// The verdict for one Pane's active item: invocation scoping gates
    /// around the pure core kind gate. Returns the verdict plus the tool and
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
        // What the audit record and the always/yes memory key on. A
        // structured (OSC 777) prompt contributes its own tool and preview;
        // a screen-detected (Phase-0 stringly) permission prompt has no
        // structured payload, so it is identified by a bounded fingerprint
        // of the live prompt region: the waiting item's summary is only the
        // matched rule text, identical for every dialog one provider
        // raises, and keying on it treated every distinct dialog inside the
        // loop window as a re-ask. The tool a screen rule cannot know is
        // "unknown".
        let (tool, preview) = match agent.details.pending_permission.as_ref() {
            Some(permission) => (permission.tool.clone(), permission.preview.clone()),
            None => {
                let fingerprint = prompt_region_fingerprint(pane_state);
                if fingerprint.is_empty() {
                    // A permission pin with no prompt content on screen is
                    // stale evidence, not a live dialog: never type an
                    // approval into a screen that cannot be identified, and
                    // never let the blank interval between two dialogs take
                    // on an identity of its own. The record still carries
                    // the sanitized summary of what was seen.
                    return (
                        uniterm_core::DelegateVerdict::Withhold {
                            reason:
                                "the prompt region is blank, so there is no live dialog to identify"
                                    .into(),
                        },
                        "unknown".to_string(),
                        uniterm_core::agent_detail::bounded_text(
                            &item.summary,
                            uniterm_core::agent_detail::DETAIL_TEXT_LIMIT,
                        ),
                        None,
                    );
                }
                ("unknown".to_string(), fingerprint)
            }
        };
        // The loop guard runs before the budget gate: the transient re-check
        // after a delegated answer would otherwise consume a verdict slot
        // and, with the last budget unit just spent, disarm an arm that has
        // seen no genuinely new prompt. The guard withholds an identical
        // prompt that comes straight back after it was plainly approved (the
        // yes reply): that is a runaway loop, not a new decision. It must
        // never block the always-to-yes escalation: when the previous answer
        // to this identity was the always reply, the resurface gets the yes
        // reply once, and only an identical re-ask after THAT withholds.
        if let Some((last_tool, last_preview, at_ms, used_always)) = &state.last_answered {
            if !used_always
                && *last_tool == tool
                && *last_preview == preview
                && now_ms.saturating_sub(*at_ms) < LOOP_GUARD_MS
            {
                return (
                    uniterm_core::DelegateVerdict::Withhold {
                        reason: "the identical prompt was auto-answered moments ago, so this re-ask looks like a loop".into(),
                    },
                    tool,
                    preview,
                    None,
                );
            }
        }
        if budget_remaining(
            state,
            self.config.delegation_policy().max_answers_per_hour,
            now_ms,
        ) == 0
        {
            // The only withhold that disarms: an arm that cannot afford the
            // next answer would look live while approving nothing.
            return (
                uniterm_core::DelegateVerdict::Withhold {
                    reason: "the hourly answer budget is exhausted; re-arm to resume".into(),
                },
                tool,
                preview,
                Some("budget_exhausted"),
            );
        }
        // The pure policy is the kind gate alone: an armed Pane approves
        // every permission prompt, structured or screen-detected, and
        // anything else stays with the human.
        let mut verdict = uniterm_core::evaluate_delegation(item.kind);
        if matches!(verdict, uniterm_core::DelegateVerdict::Allow)
            && crate::providers::approval_reply(&agent.id).is_none()
        {
            verdict = uniterm_core::DelegateVerdict::Withhold {
                reason: format!("provider {} has no verified approval reply", agent.id),
            };
        }
        (verdict, tool, preview, None)
    }

    /// Evaluate one Pane's active waiting item and, on Allow, type the
    /// provider's approval reply. The DelegationDecision record is appended
    /// BEFORE any bytes are queued, so the audit trail exists even when
    /// typing fails. On Withhold the item stays with the human. The
    /// always/yes memory is keyed on the prompt-region fingerprint for
    /// screen-detected prompts.
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
        let Some(yes_reply) = crate::providers::approval_reply(&state.agent) else {
            return;
        };
        if !still_live {
            return;
        }
        // The first answer to a prompt (per arm, keyed by the recorded
        // tool+preview identity) prefers the provider's verified
        // always-reply; when the same prompt re-surfaces inside the loop
        // window, the always keystroke did not stick for that variant and
        // the plain yes-reply answers it once (the loop guard refuses the
        // re-ask after that yes). Outside the window the prompt is a fresh
        // ask and the always preference applies again. One verdict types at
        // most one reply, so the two keystrokes never go back to back into
        // a live prompt.
        let first_sight = state.last_answered.as_ref().is_none_or({
            let (tool, preview) = (&tool, &preview);
            move |(last_tool, last_preview, at_ms, _)| {
                last_tool != tool
                    || last_preview != preview
                    || now_ms.saturating_sub(*at_ms) >= LOOP_GUARD_MS
            }
        });
        let always_reply = crate::providers::always_reply(&state.agent);
        let used_always = first_sight && always_reply.is_some();
        let reply = if used_always {
            always_reply.unwrap_or(yes_reply)
        } else {
            yes_reply
        };
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
            state.last_answered = Some((tool, preview, now_ms, used_always));
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
