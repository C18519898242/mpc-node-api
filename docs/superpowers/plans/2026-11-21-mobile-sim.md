# Mobile simulator implementation plan

**Goal:** One outbound-only embedded node plus two existing server nodes can create keys and sign, using the same MPC code and encrypted SQLite storage.

**Architecture:** Server configuration gains a `mobilePeers` mapping from party ID to authorized application ID. Servers queue MPC messages for those peers; the embedded node authenticates with its own mTLS certificate and the application's API key and polls each server. No separate broker or mobile listening port. A public `mobile` Go package wraps the embedded runtime; `cmd/mobile-sim` supplies a desktop entry point.

**Scope approved in chat:** Local simulation first; ECDSA and FROST root key creation and signing only. No Android SDK installation or APK claimed in this iteration. No export, presignature, dynamic device enrollment, offline message persistence or automatic signing retries.

**Storage:** Mobile `data/mobile-sim/node.sqlite` with the existing encrypted MK and CEK share format. A master password is mandatory for the embedded node. Server test data is isolated under `data/mobile-demo/node-2` and `node-3`. Future Android callers supply an app-private directory and a password protected by Android Keystore; that platform integration is not implemented here.

## Task 1: Authenticated outbound transport

- [x] Write failing mailbox/configuration tests: ordered delivery, redelivery until acknowledgment, invalid acknowledgments, queue limits, mobile identity and application isolation.
- [x] Add `Config.MobilePeers`; include mobile IDs in known-peer, TLS identity, signing roster and outgoing delivery lookup.
- [x] Add bounded in-memory mailboxes with timeout and per-session addressing; permit only keygen/sign routes for mobile traffic.
- [x] Add mTLS + API-key authenticated mobile control and polling routes on the existing MPC listener.
- [x] Keep existing direct HTTP peer transport and standard REST endpoints working.

## Task 2: Embedded runtime and public mobile wrapper

- [x] Add embedded configuration validation with no listener addresses.
- [x] Open encrypted SQLite and existing TLS clients without opening network listeners.
- [x] Coordinate local calls and two backend calls using one random session ID and matching players; poll incoming messages with explicit acknowledgments.
- [x] Preserve application context and cancel/close workers before clearing MK or closing the DB.
- [x] Expose `mobile.New(configJSON, dataDir, masterPassword)`, `CreateKey(algorithm, threshold, keyID)`, `Sign(algorithm, keyID, message)`, `Close()` using mobile-bindable argument types.
- [x] Compare backend results, verify signatures and return only public results.

## Task 3: Local entry point and repeatable demo

- [x] Add `cmd/mobile-sim` commands `keygen` and `sign`; resolve TLS/data paths relative to config; read secrets from environment.
- [x] Add mobile-specific configurations and one PowerShell script to launch two servers and perform create/restart/sign for both algorithms.
- [x] Record actual database paths and exact setup/run instructions in `docs/mobile-nodes.md` and link from README.

## Validation

- [x] Unit tests for boundary validation, mailbox redelivery/ack/limits and app authorization.
- [x] Integration tests with both algorithms, encrypted persistence and client reopen before signing.
- [x] Test missing/wrong credentials, canceled poll, malformed message and a mobile peer trying another application.
- [x] Run three-process HTTPS/mTLS smoke with actual local SQLite files; independently verify signatures and compare public keys before/after restart.
- [x] Run repository tests, `go vet`, independent code review and `git diff --check`.

No commits or pushes unless separately requested.
