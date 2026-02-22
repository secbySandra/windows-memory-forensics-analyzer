#!/bin/bash
# ==========================================
# Windows Forensics | Project: ANALYZER (NX212)
# Student: Sandra Golinskaya
# Unit: TMagen773631   StudentID: s8   Program: nx212
# Filename convention example: TMagen773631.s8.nx212.sh
# ------------------------------------------
# v6: full pipeline + display_results (step 7)
# ==========================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$SCRIPT_DIR/CarvedFiles_$RUN_ID"

LOG() { echo "[ $(date +'%F %T') ] $*"; }

# 1) Root check ---------------------------------------------------------------
rootcheck(){
  if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] Run this script as root (sudo)."
    exit 1
  fi
  LOG "Root check: OK (uid=$(id -u))"
}

# 2) Tools check & install ----------------------------------------------------
APT_UPDATED=0
ensure_tool(){
  local bin="$1"
  local pkg="${2:-$1}"
  if ! command -v "$bin" &>/dev/null; then
    if [[ $APT_UPDATED -eq 0 ]]; then
      LOG "Updating apt cache ..."
      apt-get update -y || true
      APT_UPDATED=1
    fi
    LOG "Installing $pkg ..."
    apt-get install -y "$pkg" || true
  fi
  LOG "Tool ready: $bin"
}

toolcheck(){
  LOG "Checking required tools ..."
  ensure_tool strings binutils
  ensure_tool binwalk binwalk
  ensure_tool bulk_extractor bulk-extractor
  ensure_tool foremost foremost
  ensure_tool zip zip
  ensure_tool unzip unzip
  LOG "All tools are ready."
}

# 3) Ask file & validate ------------------------------------------------------
TARGET=""
TARGET_ABS=""
FILETYPE=""
filecheck(){
  while :; do
    echo -n "Enter path to file for analysis: "
    read -r TARGET
    [[ -f "$TARGET" ]] && break
    echo "[WARN] File not found. Try again."
  done
  mkdir -p "$OUT_DIR"
  TARGET_ABS="$(readlink -f "$TARGET" || echo "$TARGET")"
  FILETYPE="$(file -b "$TARGET_ABS")"
  LOG "Target: $TARGET_ABS"
  LOG "file(1): $FILETYPE"
}

# 4) Extract data (carving) ---------------------------------------------------
extractdata(){
  LOG "Starting extraction into: $OUT_DIR"
  mkdir -p "$OUT_DIR"/{foremost,binwalk,bulk,strings}

  LOG "Running foremost ..."
  foremost -i "$TARGET_ABS" -o "$OUT_DIR/foremost" -q || LOG "foremost finished (or reported)."

  LOG "Running binwalk -e (with --run-as=root) ..."
  (cd "$OUT_DIR/binwalk" && binwalk -e --run-as=root "$TARGET_ABS") || LOG "binwalk finished (or reported)."

  LOG "Running bulk_extractor ..."
  bulk_extractor -o "$OUT_DIR/bulk" "$TARGET_ABS" || LOG "bulk_extractor finished (or reported)."

  LOG "Dumping strings ..."
  strings "$TARGET_ABS" > "$OUT_DIR/strings/strings.txt" || true
  LOG "strings saved -> $OUT_DIR/strings/strings.txt"

  LOG "Carving stats: total files in OUT_DIR: $(find "$OUT_DIR" -type f | wc -l)"
}

# 5) PCAP check ---------------------------------------------------------------
pcapcheck(){
  LOG "Searching for PCAP files ..."
  local found
  found="$(find "$OUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null || true)"
  if [[ -n "$found" ]]; then
    LOG "PCAP files found:"
    echo "$found" | while read -r p; do ls -lh "$p"; done
  else
    LOG "No PCAP/PCAPNG files found."
  fi
}

# 6) Volatility (standalone ./vol if present) ---------------------------------
vol2_standalone(){
  # Works only if user has downloaded ./vol (Volatility 2.6 standalone)
  if [[ ! -x "$SCRIPT_DIR/vol" ]]; then
    LOG "[INFO] ./vol not found; skipping Volatility step."
    return 0
  fi

  local VDIR="$OUT_DIR/VolatilityFiles"
  mkdir -p "$VDIR"

  LOG "Volatility2 (./vol) imageinfo ..."
  if ! "$SCRIPT_DIR/vol" -f "$TARGET_ABS" imageinfo | tee "$VDIR/imageinfo.txt" >/dev/null; then
    LOG "[WARN] Volatility imageinfo failed; maybe not a memory dump. Skipping volatility."
    return 0
  fi

  # Auto-profile (first hint from imageinfo)
  local PROFILE
  PROFILE="$(grep -m1 'Profile' "$VDIR/imageinfo.txt" | awk '{print $4}' | awk -F',' '{print $1}')"
  if [[ -z "${PROFILE:-}" ]]; then
    LOG "[WARN] Could not auto-detect profile; leaving only imageinfo."
    return 0
  fi
  LOG "Volatility profile: $PROFILE"

  # Basic plugins
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" pslist    | tee "$VDIR/pslist.txt"    >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" pstree    | tee "$VDIR/pstree.txt"    >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" cmdline   | tee "$VDIR/cmdline.txt"   >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" consoles  | tee "$VDIR/consoles.txt"  >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" psxview   | tee "$VDIR/psxview.txt"   >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" malfind   | tee "$VDIR/malfind.txt"   >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" hivelist  | tee "$VDIR/hivelist.txt"  >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" connscan  | tee "$VDIR/connscan.txt"  >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" sockscan  | tee "$VDIR/sockscan.txt"  >/dev/null || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" iehistory | tee "$VDIR/iehistory.txt" >/dev/null || true

  # Let's try dumping some "interesting" processes if their PIDs can be extracted from pslist
  mkdir -p "$VDIR/procdumps"
  # extract PID by name
  local PID_EXPL PID_WL PID_CSR
  PID_EXPL="$(awk '/explorer\.exe/ {print $3; exit}' "$VDIR/pslist.txt" || true)"
  PID_WL="$(awk '/winlogon\.exe/ {print $3; exit}' "$VDIR/pslist.txt" || true)"
  PID_CSR="$(awk '/csrss\.exe/ {print $3; exit}' "$VDIR/pslist.txt" || true)"

  [[ -n "$PID_EXPL" ]] && "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" procdump -p "$PID_EXPL" -D "$VDIR/procdumps" | tee "$VDIR/procdumps_explorer.log" >/dev/null || true
  [[ -n "$PID_WL"   ]] && "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" procdump -p "$PID_WL"   -D "$VDIR/procdumps" | tee "$VDIR/procdumps_winlogon.log" >/dev/null || true
  [[ -n "$PID_CSR"  ]] && "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" procdump -p "$PID_CSR"  -D "$VDIR/procdumps" | tee "$VDIR/procdumps_csrss.log"   >/dev/null || true

  # Mini-triage of dumps: hashes/types/first lines
  if compgen -G "$VDIR/procdumps/executable.*.exe" > /dev/null; then
    ( cd "$VDIR"
      sha256sum procdumps/executable.*.exe | tee hashes_sha256.txt >/dev/null || true
      md5sum    procdumps/executable.*.exe | tee hashes_md5.txt    >/dev/null || true
      for f in procdumps/executable.*.exe; do
        echo "### $f"             >> files_info.txt
        file "$f"                 >> files_info.txt
        strings -n 8 "$f" | head -50 >> strings_head.txt
        echo >> files_info.txt
      done
      grep -Eiao 'https?://[a-zA-Z0-9._/~:%+#?=&-]+' procdumps/executable.*.exe | sort -u > urls_in_dumps.txt || true
      grep -Eiao '[A-Za-z]:\\\\[^ \t"]{3,}'          procdumps/executable.*.exe | sort -u > win_paths_in_dumps.txt || true
    )
  fi

  LOG "Volatility artifacts saved -> $VDIR"
}

# 7) Report & ZIP + Display results ------------------------------------------
report_zip(){
  LOG "Writing project ZIP ..."
  [[ -f "$SCRIPT_DIR/Analyzer_Project.zip" ]] && rm -f "$SCRIPT_DIR/Analyzer_Project.zip"
  (cd "$SCRIPT_DIR" && zip -rq "Analyzer_Project.zip" "$(basename "$OUT_DIR")")
  LOG "ZIP ready -> $SCRIPT_DIR/Analyzer_Project.zip"
}

display_results(){
  local report="$SCRIPT_DIR/report_summary.txt"
  LOG "Writing final report -> $report"

  # Determine if there is a Volatility Files folder for the formulation (4 or 5 folders)
  local has_vol="no"
  [[ -d "$OUT_DIR/VolatilityFiles" ]] && has_vol="yes"

  {
    echo "=========================================="
    echo " Windows Forensics | Project: ANALYZER"
    echo " Student: Sandra Golinskaya"
    echo " Date (end): $(date)"
    echo " Run ID    : $RUN_ID"
    echo "=========================================="
    echo
    echo "Target file   : $TARGET_ABS"
    echo "File type     : $FILETYPE"
    echo "Output folder : $OUT_DIR"
    echo
    echo "Folders present:"
    #  list the top level subfolders
    find "$OUT_DIR" -mindepth 1 -maxdepth 1 -type d -printf "  - %f\n" | sort
    echo
    echo "Expectation:"
    if [[ "$has_vol" == "yes" ]]; then
      echo "  -> 5 folders (foremost, binwalk, bulk, strings, VolatilityFiles) + this report"
    else
      echo "  -> 4 folders (foremost, binwalk, bulk, strings) + this report"
    fi
    echo
    echo "Totals:"
    echo "  Total files in OUT_DIR: $(find "$OUT_DIR" -type f | wc -l)"
    echo "  Foremost files       : $(find "$OUT_DIR/foremost" -type f 2>/dev/null | wc -l)"
    echo "  Binwalk extracted    : $(find "$OUT_DIR/binwalk"  -type f 2>/dev/null | wc -l)"
    echo "  Bulk artifacts       : $(find "$OUT_DIR/bulk"     -type f 2>/dev/null | wc -l)"
    echo "  Strings file size    : $(wc -c < "$OUT_DIR/strings/strings.txt" 2>/dev/null || echo 0) bytes"
    if [[ "$has_vol" == "yes" ]]; then
      echo "  Volatility artifacts : $(find "$OUT_DIR/VolatilityFiles" -type f 2>/dev/null | wc -l)"
    fi
    echo
    echo "PCAP present?:"
    find "$OUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -printf "  %p (%k KB)\n" 2>/dev/null || true
    echo
    echo "Report created by analyzer.sh v6"
  } > "$report"

  LOG "Report ready: $report"
}

# ===== MAIN =====
rootcheck
toolcheck
filecheck
extractdata
pcapcheck
vol2_standalone         # will only be executed if there is ./vol and the file is actually memory
report_zip
display_results
