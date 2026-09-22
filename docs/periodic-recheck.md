# 30-day recheck

The templates in `systemd/` run `privacy-audit all` 30 days after the previous run. They are intentionally not installed or enabled.

To review before future activation:

```bash
systemd-analyze verify ~/privacy-center/systemd/privacy-audit-recheck.*
```

If you later choose to activate them, copy to `~/.config/systemd/user/`, run `systemctl --user daemon-reload`, then explicitly enable the timer. Scheduled checks use only identifiers already present in the mode-0600 identity file.
