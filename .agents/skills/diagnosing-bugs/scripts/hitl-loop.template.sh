#!/usr/bin/env bash
# Human-in-the-loop reproduction loop: copy this file to the scratchpad, edit the steps, run it.
# The agent runs the script; the person follows the prompts in their terminal.
#
#   step "<instruction>"        show the instruction, wait for Enter
#   capture VAR "<question>"    show the question, read the answer into VAR
#
# At the end the answers are printed as KEY=VALUE for the agent to read.
set -euo pipefail

step() {
  printf '\n>>> %s\n' "$1"
  read -r -p "    [Enter when done] " _
}

capture() {
  local var="$1" question="$2" answer
  printf '\n>>> %s\n' "$question"
  read -r -p "    > " answer
  printf -v "$var" '%s' "$answer"
}

# --- edit below ---------------------------------------------------------

step "Start the game (tools/r6bo.sh run) and wait for the main menu."

capture BLACK "Press F10 and close the options window again. Is the window black afterwards? (y/n)"

capture SECONDS_BLACK "If it was black: for about how many seconds? (or 'stays')"

# --- edit above ---------------------------------------------------------

printf '\n--- Captured ---\n'
printf 'BLACK=%s\n' "$BLACK"
printf 'SECONDS_BLACK=%s\n' "$SECONDS_BLACK"
