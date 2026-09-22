# Browser privacy hardening

## Firefox

- Set Enhanced Tracking Protection to **Strict**. If a site breaks, use its per-site shield exception rather than weakening the global policy.
- Block cross-site tracking cookies; periodically review site data and persistent logins.
- Enable HTTPS-Only Mode in all windows.
- Enable Global Privacy Control and “Do Not Track” (the latter is advisory and widely ignored).
- Use DNS-over-HTTPS with a trusted resolver. Network-wide AdGuard users should avoid enabling a browser resolver that bypasses local filtering unless that is intentional.
- Review location, camera, microphone, notifications and autoplay permissions; default to Ask/Block and keep explicit exceptions.
- Disable or restrict WebRTC only if IP disclosure is a demonstrated concern. Fully disabling it breaks browser calls and conferencing.
- Resist-fingerprinting/strict anti-fingerprinting settings can change timezone, fonts, canvas and window dimensions and cause visible breakage. Prefer built-in protection before custom `about:config` recipes.
- Use a password manager with a strong primary password; browser storage is acceptable only with OS disk encryption and device login protection.

## Brave

- Set Shields to aggressive tracker/ad blocking only after testing important sites; Standard causes less breakage.
- Block third-party cookies and enable HTTPS upgrades.
- Set fingerprinting protection to Standard initially; Strict may break payments, video and login flows.
- Review WebRTC IP handling. “Disable non-proxied UDP” improves VPN privacy but can degrade calls.
- Select a trusted Secure DNS provider, or disable browser Secure DNS when AdGuard must remain authoritative.
- Block notification prompts, location, camera and microphone by default; grant per site temporarily.
- Disable autoplay where practical and clear permissions for sites no longer used.
- Disable Brave Rewards/ads and optional product telemetry if unused.

## General

Use separate profiles/containers for banking, social accounts and general browsing; minimize extensions; keep automatic security updates; avoid signing the browser into unnecessary ecosystems; and test breakage after each major privacy change.
