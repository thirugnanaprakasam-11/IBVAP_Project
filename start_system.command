#!/bin/bash
# Force the script to look in M2 Homebrew and standard system paths
export PATH="/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

# Dynamically find python3 using the updated PATH
PYTHON_PATH="/Users/padmanabankrishnaswamy/IBVAP_Project/ibvap_env/bin/python3"

# Run your AI engine and desktop app
"$PYTHON_PATH" main.py &
"$PYTHON_PATH" app.py

kill %1