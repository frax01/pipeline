#!/bin/bash
# watch_ensure.sh — keep the forensic culprit_watch service alive (VM1).
# Transient systemd units die on reboot; this re-creates the unit if it is not
# active. Called from cron (every ~10 min) and @reboot. Idempotent.
systemctl is-active --quiet culprit_watch && exit 0
sudo systemctl reset-failed culprit_watch 2>/dev/null || true
sudo systemd-run --unit=culprit_watch --collect \
  -p User=tecnico -p Group=tecnico \
  -p Restart=always -p RestartSec=10 \
  /bin/bash /home/tecnico/guard_sbx/culprit_watch.sh
