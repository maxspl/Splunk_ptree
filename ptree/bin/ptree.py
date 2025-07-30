#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
ptree: Splunk custom search command for rendering process trees (or a full process forest).

Features
--------
1) Targeted mode (default):
   - Specify a root PID (and optionally a root path) to print that process's
     ancestor chain and descendants as a compact ASCII tree.

2) Forest mode:
   - If no root_pid is provided, ptree discovers all "root" processes
     (processes whose parent is unknown or missing from the dataset) and
     prints a forest, one tree per root. This is ideal for snapshot datasets
     such as CSV exports from PowerShell `Get-Process`.

3) Sorting and formatting:
   - Children and roots are sorted by creation time if available
     (via `time_field`/`time_format`), else by PID as a stable fallback.
   - Optional truncation of command lines for compact output.

4) Table mode:
   - Instead of a single multi-line tree string, emit one structured row per
     printed line with fields like pid/ppid/path/cmd/time/depth/is_root.

Notes
-----
- For event streams (e.g., long windows of Sysmon 4688 or Procmon), a full
  forest can be very large and noisy; prefer targeted mode in those cases.
- For snapshot sources (e.g., `process.csv`), forest mode gives a complete view.

Author: maxspl
"""

from __future__ import absolute_import, division, print_function, unicode_literals

import sys
import os
from collections import defaultdict
from datetime import datetime

SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
try:
    from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators
except ImportError:
    sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lib")))
    from splunklib.searchcommands import dispatch, EventingCommand, Configuration, Option, validators

LOG_PATH = "/tmp/log.txt"

import logging
from logging.handlers import RotatingFileHandler

def _get_ptree_logger():
    """
    Return a module-level logger that writes DEBUG logs to /tmp/log.txt.
    Uses a RotatingFileHandler to avoid unbounded growth.
    Guarded so we don't attach duplicate handlers on repeated imports.
    """
    logger = logging.getLogger("ptree")
    if logger.handlers:
        # Already configured in this interpreter
        return logger

    logger.setLevel(logging.DEBUG)
    fh = logging.FileHandler(LOG_PATH)
        

    fmt = logging.Formatter(
        "%(asctime)s %(process)d %(levelname)s %(name)s: %(message)s"
    )
    fh.setFormatter(fmt)
    logger.addHandler(fh)
    # Prevent double logging via root
    logger.propagate = False
    return logger

log = _get_ptree_logger()


def _to_str(v):
    """
    Safely coerce an arbitrary value to a string (Py2/3 compatible).

    Parameters
    ----------
    v : Any
        Value to convert.

    Returns
    -------
    str
        A string (never None). Returns "" for None.
    """
    try:
        if v is None:
            return ""
        return unicode(v) if "unicode" in globals() else str(v)  # noqa: F821 (Py2)
    except Exception:
        # As a last resort
        return str(v)


def _clean_text(s):
    """
    Normalize whitespace in a string and strip control characters commonly found
    in process command lines so the tree stays single-line per node.

    Parameters
    ----------
    s : str

    Returns
    -------
    str
        Condensed, single-line text.
    """
    s = (s or "")
    s = s.replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("\t", " ")
    return " ".join(s.split())


def _parse_time(value, time_format=None):
    """
    Parse a timestamp into both a display string and a sortable datetime.

    Behavior:
    - If `time_format` is provided, attempt to parse `value` as a string using strptime.
    - Otherwise try to interpret `value` as an epoch (seconds).
    - If parsing fails, return the original string and None for sorting.

    Parameters
    ----------
    value : Any
        Raw time value (string/epoch/datetime).
    time_format : str, optional
        strptime format for a string time field.

    Returns
    -------
    (str, datetime|None)
        A human-friendly display string and a datetime for sorting (or None).
    """
    if value is None:
        return "", None
    if isinstance(value, datetime):
        return value.isoformat(sep=" "), value
    s = _to_str(value).strip().strip('"').strip("'")
    if not s:
        return "", None
    if time_format:
        try:
            dt = datetime.strptime(s, time_format)
            return dt.isoformat(sep=" "), dt
        except Exception:
            # Keep original text if we can't parse it
            return s, None
    try:
        dt = datetime.fromtimestamp(float(s))
        return dt.isoformat(sep=" "), dt
    except Exception:
        return s, None


@Configuration()
class PtreeCommand(EventingCommand):
    """
    Render process trees (or a forest) from event records.

    Required options:
    -----------------
    pid_field, ppid_field, path_field, cmd_field

    Optional options:
    -----------------
    time_field:      Field containing creation time (string or epoch).
    time_format:     strptime format if time_field is a string.
    ppath_field:     Optional parent path hint (useful when the parent's event is missing).
    root_pid:        Target process ID. If omitted/empty, build a full forest.
    root_path:       Expected path for the root_pid (for logging/disambiguation).
    mode:            "tree" (default) or "table".
    truncate_cmd:    Max characters for command line (0 or empty = no limit).
    suppress_unknown_ancestors:
                     "true"/"false" — if true, hide ancestors with no event details.
    start_from_root: "true"/"false" — if true (default), start at top-most known ancestor.

    Back-compat aliases:
    --------------------
    child_name, parent_name, CreateTime_name, CreateTime_name_format,
    CommandLine_name, Process_name

    Output:
    -------
    - mode="tree": a single event with fields:
        tree, target_pid, target_path
    - mode="table": one event per printed line with fields:
        line, pid, ppid, path, cmd, time, depth, is_root, tree_prefix
    """

    # === Required fields ===
    pid_field = Option(require=True, validate=validators.Fieldname(), doc="Field holding process ID.")
    ppid_field = Option(require=True, validate=validators.Fieldname(), doc="Field holding parent process ID.")
    path_field = Option(require=True, validate=validators.Fieldname(), doc="Field holding process path/name.")
    cmd_field = Option(require=True, validate=validators.Fieldname(), doc="Field holding command line.")
    time_field = Option(require=False, validate=validators.Fieldname(), doc="Creation time field (string or epoch).")
    time_format = Option(require=False, doc="strftime format if time_field is a string.")

    # Optional hint for parent's path
    ppath_field = Option(require=False, validate=validators.Fieldname(),
                         doc="Optional field for parent process path.")

    # Target (now optional: if omitted, build full forest)
    root_pid = Option(require=False, doc="Target process ID. If omitted, build full forest.")
    root_path = Option(require=False, doc="Optional path to disambiguate target PID.")

    # Output controls
    mode = Option(require=False, validate=validators.Set("tree", "table"), doc="Output mode.")
    truncate_cmd = Option(require=False, doc="Max chars for command line; 0 or empty means no limit.")
    suppress_unknown_ancestors = Option(require=False, validate=validators.Set("true", "false"),
                                        doc="If 'true', hide ancestors that have no event details.")
    start_from_root = Option(require=False, validate=validators.Set("true", "false"),
                             doc=("If 'true', start the tree at the first known ancestor instead of the selected PID. "
                                  "Default: true."))

    # Back-compat aliases
    child_name = Option(require=False, validate=validators.Fieldname())
    parent_name = Option(require=False, validate=validators.Fieldname())
    CreateTime_name = Option(require=False, validate=validators.Fieldname())
    CreateTime_name_format = Option(require=False)
    CommandLine_name = Option(require=False, validate=validators.Fieldname())
    Process_name = Option(require=False, validate=validators.Fieldname())

    # ----------------------------
    # Internal helpers / lifecycle
    # ----------------------------

    def _resolve_field_aliases(self):
        """
        Apply backward-compat aliases and set defaults for unspecified options.
        """
        if not self.pid_field and self.child_name:
            self.pid_field = self.child_name
        if not self.ppid_field and self.parent_name:
            self.ppid_field = self.parent_name
        if not self.path_field and self.Process_name:
            self.path_field = self.Process_name
        if not self.cmd_field and self.CommandLine_name:
            self.cmd_field = self.CommandLine_name
        if not self.time_field and self.CreateTime_name:
            self.time_field = self.CreateTime_name
        if not self.time_format and self.CreateTime_name_format:
            self.time_format = self.CreateTime_name_format
        if not self.mode:
            self.mode = "tree"
        if self.start_from_root is None:
            self.start_from_root = "true"

    def _make_line(self, pid, meta):
        """
        Build a fixed-width, single-line textual representation for a node.

        Parameters
        ----------
        pid : str
            PID to print.
        meta : dict
            Dict with keys: ppid, path, cmd, time_display

        Returns
        -------
        str
            Formatted line: "<pid> <path:50> <time:23> <cmd>"
        """
        pid_s = _to_str(pid)
        path_s = _clean_text(meta.get("path", ""))
        t_disp = meta.get("time_display", "")
        cmd_s = _clean_text(meta.get("cmd", ""))

        try:
            # Safe parsing of truncate option
            tlim = int(self.truncate_cmd) if self.truncate_cmd is not None and _to_str(self.truncate_cmd) != "" else 0
        except Exception:
            tlim = 0

        if tlim and len(cmd_s) > tlim:
            cmd_s = cmd_s[: max(0, tlim - 1)] + "…"

        return "{:<6} {:<50} {:<23} {}".format(pid_s, (path_s or "")[:50], (t_disp or "")[:23], cmd_s or "")

    # ----------------------------
    # Splunk command entry point
    # ----------------------------
    def transform(self, records):
        """
        Main entry: consume input events and yield either:
        - a single aggregated "tree" event (mode=tree), or
        - multiple row events (mode=table).

        Notes
        -----
        - Keeps the earliest-seen event per PID based on `time_field` for stable trees.
        - Uses DFS for child rendering with deterministic ordering.
        """
        self._resolve_field_aliases()
        hide_unknown = (_to_str(self.suppress_unknown_ancestors).lower() == "true")
        start_at_root = (_to_str(self.start_from_root).lower() == "true")

        # Cache events and relationships
        rows = list(records)
        log.debug(f"MSP events : {len(rows)}")
        by_pid = {}
        children = defaultdict(list)
        parent_hints = {}  # PID -> parent path (from child's parent_process_path)

        # --- Target selection flags (strict pid+path when both are provided) ---
        target_pid = _to_str(self.root_pid).strip()
        expected_path = _to_str(self.root_path).strip()
        forest_mode = (target_pid == "")
        strict_root = (not forest_mode and expected_path != "")

        # --- Build indexes ---
        for r in rows:
            pid = _to_str(r.get(self.pid_field)).strip()
            ppid = _to_str(r.get(self.ppid_field)).strip()
            path = _to_str(r.get(self.path_field)).strip()
            cmd = _to_str(r.get(self.cmd_field)).strip()
            t_raw = r.get(self.time_field) if self.time_field else None
            t_display, t_sort = _parse_time(t_raw, self.time_format)

            if not pid:
                continue

            # Strict targeting: if both root_pid and root_path were provided,
            # ignore records for that PID whose path doesn't match exactly.
            if strict_root and pid == target_pid and path != expected_path:
                continue

            # Keep the earliest event per PID to stabilize trees
            prior = by_pid.get(pid)
            if prior is None or (
                prior.get("t_sort") is not None and t_sort is not None and t_sort < prior["t_sort"]
            ):
                by_pid[pid] = {
                    "ppid": ppid,
                    "path": path,
                    "cmd": cmd,
                    "time_display": t_display,
                    "t_sort": t_sort,
                }

            if ppid:
                children[ppid].append(pid)
                # Capture a helpful hint for a missing parent (if present)
                if self.ppath_field:
                    ppath = _to_str(r.get(self.ppath_field)).strip()
                    if ppath:
                        parent_hints.setdefault(ppid, ppath)

        # --- Sorting helpers ---
        def sorted_children(pid):
            """
            Return children of `pid` sorted by creation time (then PID).
            """
            kids = children.get(pid, [])

            def keyfn(k):
                m = by_pid.get(k, {})
                ts = m.get("t_sort")
                return (ts if ts is not None else datetime.max, _to_str(k))

            return sorted(kids, key=keyfn)

        # Collection buffers
        lines = []           # printable text lines (mode=tree)
        table_rows = []      # structured rows (mode=table)

        def append_print_line(pid, meta, depth, is_root, prefix="", branch=""):
            """
            Append a printable line and mirror it to `table_rows` if needed.

            Parameters
            ----------
            pid : str
            meta : dict
            depth : int
            is_root : bool
            prefix : str
                Tree drawing prefix (guides/whitespace).
            branch : str
                "├── " / "└── " or "" for root/ancestor lines.
            """
            text = (prefix + branch + self._make_line(pid, meta)) if (prefix or branch) else self._make_line(pid, meta)
            lines.append(text)
            if self.mode == "table":
                table_rows.append({
                    "line": text,
                    "tree_prefix": prefix + branch,
                    "pid": _to_str(pid),
                    "ppid": _to_str(meta.get("ppid", "")),
                    "path": _to_str(meta.get("path", "")),
                    "cmd": _to_str(meta.get("cmd", "")),
                    "time": _to_str(meta.get("time_display", "")),
                    "depth": depth,
                    "is_root": "true" if is_root else "false",
                })

        # Depth-first traversal for descendants
        def dfs(pid, depth=0, prefix=""):
            """
            Recursive DFS to print children of `pid`.
            """
            kids = sorted_children(pid)
            for i, child in enumerate(kids):
                last = (i == len(kids) - 1)
                branch = "└── " if last else "├── "
                meta = by_pid.get(child, {"path": "", "cmd": "", "time_display": ""})
                append_print_line(child, meta, depth + 1, False, prefix, branch)
                dfs(child, depth + 1, prefix + ("    " if last else "│   "))

        # --- Mode selection: forest vs targeted ---
        if forest_mode:
            # root_path does not make sense without a PID
            if self.root_path:
                self.logger.info("root_path provided without root_pid; ignoring root_path in forest mode.")

            # Identify roots: parent missing or unknown in this dataset
            def root_key(pid):
                m = by_pid.get(pid, {})
                ts = m.get("t_sort")
                return (ts if ts is not None else datetime.max, _to_str(pid))

            roots = []
            for pid, meta in by_pid.items():
                ppid = meta.get("ppid")
                if not ppid or ppid not in by_pid:
                    roots.append(pid)

            roots = sorted(set(roots), key=root_key)

            # Print each tree (blank line between)
            for idx, root in enumerate(roots):
                if idx > 0:
                    # Represent the separation as an empty line in tree mode only.
                    # For table mode, we don't emit an empty row.
                    lines.append("")
                append_print_line(root, by_pid.get(root, {}), depth=0, is_root=True)
                dfs(root, depth=0, prefix="")

            # Emit results
            if self.mode == "table":
                for row in table_rows:
                    yield row
            else:
                yield {
                    "tree": "\n".join(lines),
                    "target_pid": "",
                    "target_path": "",
                }
            return

        # --- Targeted mode (strict if root_path given) ---
        if strict_root and (target_pid not in by_pid or by_pid[target_pid].get("path") != expected_path):
            yield {"_error": "Target PID {} with path {} not found in events."
                             .format(target_pid or "<empty>", expected_path or "<empty>")}
            return

        if target_pid not in by_pid:
            yield {"_error": "Target PID {} not found in events.".format(target_pid or "<empty>")}
            return

        # Build ancestor chain: top-most -> ... -> direct parent of target
        ancestors = []
        visited = set()
        cur = target_pid
        while True:
            meta = by_pid.get(cur)
            if not meta:
                break
            ppid = meta.get("ppid")
            if not ppid or ppid in visited or ppid == cur:
                break
            ancestors.append(ppid)
            visited.add(ppid)
            if ppid in by_pid:
                cur = ppid
            else:
                break
        ancestors = list(reversed(ancestors))

        # Find the first known ancestor (top-most with details)
        top_known = None
        for a in ancestors:
            if a in by_pid:
                top_known = a
                break

        if start_at_root and top_known:
            # Option A: Start from the top-most known ancestor
            # Print unknown ancestors above it unless suppressed
            if not hide_unknown:
                for a in ancestors:
                    if a == top_known:
                        break
                    meta = {
                        "ppid": "",
                        "path": parent_hints.get(a, "[parent not in events/time range]"),
                        "cmd": "",
                        "time_display": "[unknown]",
                    }
                    append_print_line(a, meta, depth=0, is_root=False)

            # Print chosen root and descendants
            append_print_line(top_known, by_pid.get(top_known, {}), depth=0, is_root=True)
            dfs(top_known, depth=0, prefix="")
        else:
            # Option B: Print the whole chain down to target, then expand
            for a in ancestors:
                meta = by_pid.get(a)
                if not meta:
                    if hide_unknown:
                        continue
                    meta = {
                        "ppid": "",
                        "path": parent_hints.get(a, "[parent not in events/time range]"),
                        "cmd": "",
                        "time_display": "[unknown]",
                    }
                append_print_line(a, meta, depth=0, is_root=False)

            # Target and descendants
            append_print_line(target_pid, by_pid[target_pid], depth=0, is_root=True)
            dfs(target_pid, depth=0, prefix="")

        # Emit results
        if self.mode == "table":
            for row in table_rows:
                yield row
        else:
            yield {
                "tree": "\n".join(lines),
                "target_pid": target_pid,
                "target_path": by_pid.get(target_pid, {}).get("path", ""),
            }


# Dispatch entry for Splunk
dispatch(PtreeCommand, sys.argv, sys.stdin, sys.stdout, __name__)
