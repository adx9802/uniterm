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

Two keys bound what an armed pane may auto-approve (see [06-agentic-supervision.md](06-agentic-supervision.md)):

```ini
# ~/.config/uniterm/uniterm.conf
delegation-allow = git status        # repeatable: program plus optional argument prefix
delegation-allow = cargo test
delegation-max-answers-per-hour = 30 # 1..240, default 30
```

`delegation-allow` is an allowlist on top of a compiled-in deny floor, not a replacement for it: privilege escalation, network actors, destructive filesystem and git operations, credential and dotfile paths, shell substitution or chaining, and any path escaping the pane's Project root withhold no matter what is configured.
A rule matches when the pending tool call's program equals the rule's program and its arguments start with the rule's argument prefix on a shell-word boundary, and every path-like argument must resolve inside the Project root.
At most 64 rules of 256 bytes each are kept; extras are diagnosed and dropped.
When the hourly budget is spent the arm disarms itself until the human re-arms, and `ut config check` reports every delegation key problem as an error.
