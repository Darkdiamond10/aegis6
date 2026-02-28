# Session State

## Current Status
We successfully diagnosed and solved the root cause of the initial memory overflow `Segmentation fault`. The stager `aegis_stager` was originally trying to read a ~5.7 MB static `ghost_loader` binary into a fixed 1 MB buffer `AEGIS_C2_MAX_PAYLOAD_SIZE`. 

We accomplished the following:
1. Updated `AEGIS_C2_MAX_PAYLOAD_SIZE` to 25 MB (`25 * 1024 * 1024`) in `common/config.h` to act as an upper safety bound rather than a strict allocation size.
2. Completely removed fixed-size buffers in `c2_comms/c2_client.c`.
3. Designed and injected a new dynamic parsing function (`tls_recv_dynamic`) that safely reallocates the correct amount of memory to fit incoming payload sizes accurately, ensuring maximum OpSec stealth.

After applying these fixes, the primary buffer overflow was eliminated. However, a new localized crash happens right after the payload completely downloads.

## Blocker/Error
The `aegis_stager` process successfully requests, downloads, and attempts to decrypt the Ghost Loader payload into a dynamically allocated `stage_out` buffer via OpenSSL. However, OpenSSL's `EVP_DecryptUpdate` and `EVP_DecryptFinal_ex` expect the output buffer to handle up to an additional block size (`+ 16` bytes) to finalize padding during symmetric decryption. 

Because we `malloc(stage_ct_len)` for exact fits, writing the very end of the decrypted AES-GCM data occasionally overwrites the heap boundary by a few bytes, triggering a final `Segmentation fault` inside OpenSSL/glibc memory allocation when freeing or wiping the buffer.

## Next Steps
1. In `c2_comms/c2_client.c`, slightly increase the output buffer size padding for OpenSSL operations. When allocating memory for the decryption buffer (e.g., `*stage_out = malloc(stage_ct_len);`), update it to `malloc(stage_ct_len + 16);` or `malloc(stage_ct_len + EVP_MAX_BLOCK_LENGTH);`.
2. Recompile `aegis_stager`.
3. Verify full communication and decryption with the local C2 server ensuring `ghost_loader` cleanly copies to `memfd` and executes without boundary faults.
