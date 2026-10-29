# Configuring Uniterm

The config file, the bundled themes, and the provider detection manifests.
The Settings modal (`Ctrl-A g`, see [USAGE.md](USAGE.md)) edits the same file and preserves anything it does not own.

Uniterm reads a Ghostty-style `key = value` config from `~/.config/uniterm/uniterm.conf`.
Unknown keys are ignored, so it is forgiving.

```ini
# ~/.config/uniterm/uniterm.conf
prefix = C-a               # the prefix key (e.g. C-a, C-b)
status = on                # show the status line
status-position = top      # top | bottom
scrollback-limit = 10000
theme = uniterm-dark       # select any bundled semantic theme
sidebar = true
sidebar-width = 24         # 16..40; responsive at runtime
file-sidebar = true        # legacy name: show the right Observatory rail
file-sidebar-width = 36    # Observatory width, 22..52
notification-delivery = uniterm  # off | uniterm | terminal | system
notify-completion = false  # also notify when an agent becomes idle
notification-sound = bell  # off | bell | chime | file
notification-sound-file =  # audio file used when notification-sound = file
focus-follows-mouse = false
freeze-on-select = false   # hold the screen still while selecting; a drag selects even in apps that take the mouse
copy-on-select = true      # copy a drag selection to the clipboard on release
confirm-close = true
restore = true             # resurrect a saved Workspace on start (alias: autosave)
```

Bundled semantic themes are Uniterm dark/light, Catppuccin, Tokyo Night, Dracula, Nord, Gruvbox dark/light, Solarized dark/light, Kanagawa, and Rose Pine.
The same Settings control also includes 178 [Omarchy palettes](../themes/omarchy/README.md): all 22 upstream themes, 145 of 146 community gallery themes, and 11 local additions captured on 2026-10-01.
Use `omarchy-*`, `omarchy-community-*`, or `omarchy-local-*` names from the [full catalog](../themes/omarchy/CATALOG.md), for example `theme = omarchy-local-minimal` for the user's Felix-derived Minimal theme.
Gruvu and the local Aether theme are intentionally excluded; theme selection uses bundled data without network access or desktop configuration changes.
Theme roles style the top bar, Tabs, borders, and client dialogs, including a surface-blended secondary accent for buttons that keeps the active Tab and Project visually dominant.
The sidebar and application canvas retain terminal-native colours, and child application colours are never dimmed or recoloured for focus.

Local agent providers can be added or overridden without rebuilding, and a valid atomic replacement hot-reloads on the Tokio runtime:

```json
{
  "schema_version": 1,
  "manifest_version": "my-team-1",
  "providers": [{
    "id": "my-agent",
    "executable_aliases": ["my-agent"],
    "capabilities": ["process", "screen"],
    "rules": [{
      "id": "screen.permission",
      "evidence": "screen",
      "status": "permission",
      "pattern": "approval required",
      "confidence": 95,
      "dwell_ms": 5000
    }]
  }]
}
```

Save that document as `$XDG_CONFIG_HOME/uniterm/providers.json` (normally `~/.config/uniterm/providers.json`).
Validate it offline with `ut agent manifests validate PATH`.
The complete schema, source precedence, verified cache, last-known-good, and reload contract is in [`22-provider-detection-manifests.md`](22-provider-detection-manifests.md).

## Delegated answering

Two keys govern delegated answering (see [06-agentic-supervision.md](06-agentic-supervision.md)):

```ini
# ~/.config/uniterm/uniterm.conf
delegation-auto-arm = off # default off
delegation-max-answers-per-hour = 30 # 1..240, default 30; ignored while auto-arm is on
```

Arming a pane (`ut delegate arm PANE`) approves every permission prompt that invocation raises, structured or screen-detected; there is no command allowlist or deny floor, so the arm is the whole consent.
With `delegation-auto-arm` off, a manual arm disarms itself when the hourly budget is spent and stays disarmed until the human re-arms.
With `delegation-auto-arm` on (Yolo Mode), every live pane running a provider with a verified approval reply is kept armed and approves every permission prompt with no hourly budget: fresh bindings arm, turning the switch on arms panes that were already bound, and a pane whose arm dropped is re-armed at its next permission prompt.
Only an explicit `ut delegate disarm PANE` holds against Yolo Mode, for the rest of that invocation; questions are never auto-answered either way.
`delegation-max-answers-per-hour` is still validated while Yolo Mode is on and applies again the moment it is turned off, so `ut config check` reports a bad value either way rather than letting Yolo Mode hide it.
The client Settings surface exposes `delegation-auto-arm` as the "Yolo Mode" switch ("auto type A or Y") and flips it live on the running server through the same atomic settings save as every other row; turning it off leaves current arms alive with the budget restored.
`ut config check` reports every delegation key problem as an error, and the retired `delegation-allow` key is diagnosed as an unknown key, so an old config cannot look like it still gates approvals.
