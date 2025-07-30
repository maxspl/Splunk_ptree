# Splunk ptree cmd

`ptree` is a custom Splunk **EventingCommand** that prints process **trees** (for a specific PID) or a complete process **forest** (all roots) from your events.
Other apps didn't work for me since my data source (powershell Get-Process) sometimes causes infinite loops.

It works with:
- **Snapshot** datasets (CSV/lookup) such as PowerShell `Get-Process` exports → use **forest mode** (no `root_pid`).
- **Event** datasets (Sysmon 1, Security 4688) → use **targeted mode** (`root_pid=<pid>`).

Algorithm stolen here: https://stackoverflow.com/questions/16395207/create-a-process-tree-like-pstree-command-with-python-in-linux

## Installation

Clone ptree repo to your splunk app folder.

### Install in existing app

1. Copy `ptree.py` into your app’s `bin/` directory:

   ```
   $SPLUNK_HOME/etc/apps/<your_app>/bin/ptree.py
   ```

2. Ensure `splunklib` is available. Most Splunk app skeletons include it under `lib/`.  
   The script adds:
   ```
   $SPLUNK_HOME/etc/apps/splunk_investigation_app/lib
   ```
   to `sys.path`. Adjust if your app uses a different lib path or vendor `splunklib` elsewhere.

3. Register the custom command in `commands.conf`:

   ```ini
   [ptree]
   filename = ptree.py
   generating = false
   type = eventing
   supports_rawargs = true
   ```

Restart Splunk or reload the app as needed.
--- 

## Usage

### Field Requirements

You must map these fields (option names on the left, your field names on the right):

- `pid_field`  → **Process ID**
- `ppid_field` → **Parent Process ID**
- `path_field` → **Process path/name**
- `cmd_field`  → **Command line**

Optional:
- `time_field`  → creation time (string or epoch)
- `time_format` → strptime format if `time_field` is a string
- `ppath_field` → parent’s path (hint only, shown when the parent event is missing)

### 1) Forest mode (no `root_pid`) — best for snapshots

Render a full process forest from a CSV/lookup:

```spl
| inputlookup process.csv
| ptree pid_field=PID ppid_field=PPID path_field=Path cmd_field=CommandLine time_field=CreateTime time_format="%Y-%m-%d %H:%M:%S" truncate_cmd=100
| table *
```

### 2) Targeted mode (with `root_pid`) — best for event streams

Render a specific process and descendants:

```spl
... your search producing 4688-like events ...
| ptree pid_field=pid ppid_field=ppid path_field=process cmd_field=cmdline time_field=_time root_pid=4321 root_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" truncate_cmd=100
| table *
```

### 2-bis) Targeted mode (with `root_pid` and `root_path`) — best for event streams

Render a specific process and descendants:

```spl
... your search producing 4688-like events ...
| ptree pid_field=pid ppid_field=ppid path_field=process cmd_field=cmdline time_field=_time root_pid=4321 root_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" truncate_cmd=100
| table *
```

### 3) Show as a table instead of a single big string

```spl
| inputlookup process.csv
| ptree pid_field=PID ppid_field=PPID path_field=Path cmd_field=CommandLine mode=table
| table *
```

`mode=table` emits one event per printed line with:
- `line`        – the same text you’d see in tree mode
- `tree_prefix` – guides for where the node sits (`├──`, `└──`, etc.)
- `pid`, `ppid`, `path`, `cmd`, `time`
- `depth`       – 0 for roots, increasing by 1 per level
- `is_root`     – `"true"` or `"false"`

---

## Options (quick reference)

- `pid_field`, `ppid_field`, `path_field`, `cmd_field` **(required)**
- `time_field`, `time_format` — sort by creation time if provided; else by PID
- `ppath_field` — show parent path hint when parent event is missing
- `root_pid` — **omit to build a full forest**
- `root_path` — expected path for `root_pid`; used for logging only
- `mode` — `"tree"` (default) or `"table"`
- `truncate_cmd` — max length for command line (default unlimited)
- `suppress_unknown_ancestors` — `"true"` to hide unknown ancestors
- `start_from_root` — `"true"` (default) to start at top-most known ancestor

---
### Example
![Alt text](/assets/screenshot.png)

---

## Tips & Caveats

- **Scope by host/session**: If your dataset contains multiple hosts/snapshots, filter (`host=...`) or group appropriately before `ptree` to avoid mixing unrelated trees.
- **Event multiplicity**: The command keeps the **earliest** event per PID (by `time_field`) to make parent/child ordering stable.
- **Large forests**: On busy servers, forest output can be huge. Time-bound your search or add filters to keep it readable.
- **Parent hints**: If the parent’s event is missing (outside time range, dropped, etc.), setting `ppath_field` lets `ptree` print a helpful hint like `"[parent not in events/time range]"` with a best-effort path.
