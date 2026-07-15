# Manual Testing

1. Open the site over plain HTTP and verify the HTTPS check warns.
2. Open it over HTTPS and verify the HTTPS check passes.
3. Test without a VPN and note the server-seen public IP.
4. Test with a VPN and verify the server IP changes.
5. Disable WebRTC and confirm the UI reports it as blocked/protective.
6. Test in Chrome, Firefox and Safari-compatible browsers.
