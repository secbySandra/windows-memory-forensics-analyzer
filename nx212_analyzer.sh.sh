#!/bin/bash
# ==================================================
# Windows Memory Forensics Analyzer
# Automated DFIR Triage Pipeline
# --------------------------------------------------
# Version: 1.0
# Author: Sandra Golinskaya
# --------------------------------------------------
# This tool automates Windows memory dump triage:
# - Artifact carving
# - PCAP detection
# - Volatility-based memory analysis
# - Process dumping & hashing
# - Structured evidence packaging
# ==================================================

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
RUN_ID="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$SCRIPT_DIR/Forensic_Run_$RUN_ID"

LOG() { echo "[ $(date +'%F %T') ] $*"; }

# Root check ---------------------------------------------------------------
rootcheck(){
  if [[ $(id -u) -ne 0 ]]; then
    echo "[ERROR] Run this script as root (sudo)."
    exit 1
  fi
  LOG "Root privileges verified."
}

# Tool check & install ----------------------------------------------------
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
  LOG "All required tools verified."
}

# Target file input --------------------------------------------------------
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

  LOG "Target file: $TARGET_ABS"
  LOG "Detected type: $FILETYPE"
}

# Artifact carving ---------------------------------------------------------
extractdata(){
  LOG "Starting artifact extraction into: $OUT_DIR"
  mkdir -p "$OUT_DIR"/{foremost,binwalk,bulk,strings}

  LOG "Running foremost ..."
  foremost -i "$TARGET_ABS" -o "$OUT_DIR/foremost" -q || true

  LOG "Running binwalk ..."
  (cd "$OUT_DIR/binwalk" && binwalk -e --run-as=root "$TARGET_ABS") || true

  LOG "Running bulk_extractor ..."
  bulk_extractor -o "$OUT_DIR/bulk" "$TARGET_ABS" || true

  LOG "Extracting strings ..."
  strings "$TARGET_ABS" > "$OUT_DIR/strings/strings.txt" || true

  LOG "Extraction complete. Total files: $(find "$OUT_DIR" -type f | wc -l)"
}

# PCAP detection -----------------------------------------------------------
pcapcheck(){
  LOG "Searching for PCAP artifacts ..."
  local found
  found="$(find "$OUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null || true)"
  if [[ -n "$found" ]]; then
    LOG "PCAP artifacts detected:"
    echo "$found"
  else
    LOG "No PCAP artifacts detected."
  fi
}

# Volatility analysis ------------------------------------------------------
volatility_analysis(){
  if [[ ! -x "$SCRIPT_DIR/vol" ]]; then
    LOG "Volatility standalone binary not found (./vol). Skipping memory analysis."
    return 0
  fi

  local VDIR="$OUT_DIR/Volatility"
  mkdir -p "$VDIR"

  LOG "Running imageinfo ..."
  if ! "$SCRIPT_DIR/vol" -f "$TARGET_ABS" imageinfo | tee "$VDIR/imageinfo.txt" >/dev/null; then
    LOG "Volatility imageinfo failed. Skipping further memory analysis."
    return 0
  fi

  PROFILE="$(grep -m1 'Profile' "$VDIR/imageinfo.txt" | awk '{print $4}' | awk -F',' '{print $1}')"
  [[ -z "$PROFILE" ]] && { LOG "Profile auto-detection failed."; return 0; }

  LOG "Detected profile: $PROFILE"

  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" pslist   > "$VDIR/pslist.txt"   || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" pstree   > "$VDIR/pstree.txt"   || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" psxview  > "$VDIR/psxview.txt"  || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" malfind  > "$VDIR/malfind.txt"  || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" hivelist > "$VDIR/hivelist.txt" || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" connscan > "$VDIR/connscan.txt" || true
  "$SCRIPT_DIR/vol" -f "$TARGET_ABS" --profile="$PROFILE" sockscan > "$VDIR/sockscan.txt" || true

  LOG "Volatility analysis completed."
}

# Report generation --------------------------------------------------------
generate_report(){
  local report="$SCRIPT_DIR/report_summary.txt"

  {
    echo "=========================================="
    echo " Windows Memory Forensics Analyzer"
    echo " Automated DFIR Triage Report"
    echo "=========================================="
    echo
    echo "Date: $(date)"
    echo "Run ID: $RUN_ID"
    echo
    echo "Target File: $TARGET_ABS"
    echo "File Type  : $FILETYPE"
    echo "Output Dir : $OUT_DIR"
    echo
    echo "Total Extracted Files: $(find "$OUT_DIR" -type f | wc -l)"
    echo
    echo "PCAP Artifacts:"
    find "$OUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) -printf "  %p\n" 2>/dev/null || true
    echo
    echo "Report generated by Windows Memory Forensics Analyzer v1.0"
  } > "$report"

  LOG "Report created -> $report"
}

# ZIP packaging ------------------------------------------------------------
package_results(){
  local zipname="Forensic_Run_$RUN_ID.zip"
  (cd "$SCRIPT_DIR" && zip -rq "$zipname" "$(basename "$OUT_DIR")")
  LOG "Evidence archive created -> $SCRIPT_DIR/$zipname"
}

# ================= MAIN =================
rootcheck
toolcheck
filecheck
extractdata
pcapcheck
volatility_analysis
generate_report
package_results
