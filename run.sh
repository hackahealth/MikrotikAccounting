#!/usr/bin/env bash
# اجرای بدون Docker روی لینوکس:  ./run.sh
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
pip install -q -r requirements.txt
set -a; [ -f .env ] && . ./.env; set +a
exec python -m app.main
