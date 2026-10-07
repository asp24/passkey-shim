# 02. CTAPHID_CANCEL is ignored while a prompt is open

## Problem

`internal/ctaphid/ctaphid.go`, `runWithKeepalive` (around line 216) documents
it: the transport runs the CTAP2 handler and sends keepalives, but does not
read new packets until the handler returns. A `CTAPHID_CANCEL` from the
browser (the user clicked Cancel in the browser dialog, or picked another
key) is only seen after the prompt closes. The desktop prompt stays on screen
for a request the browser already abandoned, and a second request queues
behind it.

CTAP 2.1 §11.2.9.1.5 expects the authenticator to stop the operation and
answer `CTAP2_ERR_KEEPALIVE_CANCEL` (0x2D).

## Proposed approach

Depends on the context plumbing described in 01.

1. Run the handler with a per-request context:
   `ctx, cancel := context.WithCancel(parent)`, store `cancel` keyed by
   channel id.
2. Keep reading packets while the handler runs. The read loop lives in
   `cmd/llavero/daemon.go` and calls `HandlePacket`, so `runWithKeepalive`
   must stop blocking: start the handler in a goroutine and return, sending
   the response from that goroutine. Sends must then be serialised (one mutex
   around `sendMessage`/`sendKeepalive`), because keepalives and responses for
   different channels can interleave.
3. On `CTAPHID_CANCEL` for a channel with a request in flight, call its
   `cancel`. The handler returns 0x2D, which is sent as the CBOR response.
4. A new request on a busy channel answers `CTAPHID_ERROR` with
   `ERR_CHANNEL_BUSY` (0x06).

## Trade-offs

- `Transport` stops being single-goroutine; its doc comment and the `pending`
  map need a lock.
- Only one prompt can be on screen at a time anyway, so a second channel's
  request should probably get `ERR_CHANNEL_BUSY` too rather than queue.

## Done when

- A ctaphid test sends a CBOR request whose handler blocks on ctx, then
  CANCEL on the same channel, and receives status 0x2D promptly.
- A request on a busy channel gets `ERR_CHANNEL_BUSY`.
- Tests pass with `-race`.
