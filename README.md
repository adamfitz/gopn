# gopn — OPNsense Automation CLI

A modular Go CLI for auditing and automating OPNsense firewall configuration
via the REST API, built on [browningluke/opnsense-go](https://github.com/browningluke/opnsense-go).

---

## Installation

```bash
git clone https://github.com/adamfitz/gopn
cd gopn
go mod tidy
go build -o gopn .
mv gopn /usr/local/bin/gopn   # optional
```

Requires **Go 1.22+**.

---

## First run — create your config

Config is stored at `~/.config/gopn/config.json`.

**Interactive wizard (recommended):**
```bash
gopn init
```

**Manual creation** — create `~/.config/gopn/config.json`:
```json
{
  "host": "https://192.168.1.1",
  "api_key": "your-api-key",
  "api_secret": "your-api-secret",
  "allow_insecure": true
}
```

`allow_insecure: true` is required for OPNsense instances using self-signed
TLS certificates (the default for most lab setups).

Generate an API key/secret pair in OPNsense under
**System > Access > Users > Edit > API keys**.

---

## Commands

### Global flags

| Flag | Default | Description |
|------|---------|-------------|
| `--json` | false | Output as pretty-printed JSON instead of a table (available on every command) |

---

### `gopn init`
Create or recreate `~/.config/gopn/config.json` interactively.

---

### `gopn fw rules`
Fetch and display all configured firewall filter rules.

```bash
gopn fw rules
gopn fw rules --json
```

---

### `gopn fw duplicates`
Identify rules that are **logically identical**.

Comparison key: action + direction + interface + ip_protocol + protocol +
source net/port + dest net/port + gateway.  UUID, description, log, and
sequence are intentionally excluded.

```bash
gopn fw duplicates
gopn fw duplicates --json
```

---

### `gopn fw consolidate`
Suggest rules that **could be merged** into a single rule with an OPNsense
port alias — rules sharing the same source/dest networks, action, interface,
and protocol but with different destination ports.

gopn never modifies your firewall. This command is read-only analysis only.

```bash
gopn fw consolidate
gopn fw consolidate --json
```

---

## JSON output format

`gopn fw rules --json` → `[]Rule`

`gopn fw duplicates --json` and `gopn fw consolidate --json` → `AnalysisResult`:
```json
{
  "rules": [...],
  "duplicates": [...],
  "consolidation_suggestions": [...]
}
```

The `Rule` struct:
```json
{
  "uuid": "a1b2c3d4-...",
  "enabled": true,
  "action": "pass",
  "direction": "in",
  "interface": "lan",
  "ip_protocol": "inet",
  "protocol": "TCP",
  "source_net": "any",
  "source_port": "any",
  "dest_net": "10.0.0.5",
  "dest_port": "443",
  "gateway": "",
  "description": "Allow HTTPS",
  "log": false,
  "sequence": "1"
}
```

---

## Architecture

```
gopn/
├── main.go
├── go.mod
├── README.md
├── cmd/
│   ├── root.go        ← Cobra root, global --json flag, gopn init
│   └── fw.go          ← gopn fw rules | duplicates | consolidate
└── pkg/
    ├── parser/        ← WriteJSON, ReadJSON, ToBool, ToString, Coalesce ...
    ├── config/        ← AppConfig, Load/Save, first-run wizard, MissingConfigError
    ├── httpclient/    ← Builds opnsense.Client from AppConfig (only opnsense-go importer)
    └── fwrules/       ← Rule struct, FetchAll, FindDuplicates, FindConsolidations,
                          AnalysisResult, table and JSON renderers
```

### Package responsibilities

| Package | Responsibility |
|---------|---------------|
| `pkg/parser` | Zero-domain generic utilities: JSON file I/O, `ToString`, `ToBool`, `Coalesce`, path helpers. Safe to import from any package. |
| `pkg/config` | Single source of truth for `~/.config/gopn/config.json`. Handles first-run prompting, validation, load, and save. Only imports `parser`. |
| `pkg/httpclient` | Translates `AppConfig` into a live `opnsense.Client`. The **only** package that imports `opnsense-go/pkg/api` and `opnsense-go/pkg/opnsense`. |
| `pkg/fwrules` | All firewall logic and rendering. Defines application structs. Imports `opnsense-go/pkg/firewall` only in `fromLibRule` — the adapter layer. |
| `cmd/` | Cobra command wiring. No business logic. Reads `JSONOutput` global flag. |

---

## Extending the app

To add a new OPNsense service (e.g. NAT rules, aliases):

1. Create `pkg/<service>/<service>.go` — domain structs, fetch, analysis, renderers.
2. Create `cmd/<service>.go` — Cobra parent + sub-commands, reading `JSONOutput`.
3. Register the parent in `cmd/root.go` `init()`.

`pkg/parser`, `pkg/config`, and `pkg/httpclient` require no changes.

---

## Dependencies

| Module | Purpose |
|--------|---------|
| `github.com/browningluke/opnsense-go` | OPNsense REST API client |
| `github.com/spf13/cobra` | CLI framework |
| `github.com/olekukonko/tablewriter` | Terminal table rendering |
