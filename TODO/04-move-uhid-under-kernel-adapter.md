# 04. Move internal/uhid under the kernel adapter

## Problem

`internal/uhid` (the raw `/dev/uhid` binding) and
`internal/hidbridge/kernel` (the adapter that implements `hidbridge.Device`
on top of it) have confusingly similar names. Today only the adapter imports
`internal/uhid`, but nothing stops another package from using the raw
binding directly and bypassing the protocol boundary the broker exists for.

## Proposed approach

Move `internal/uhid` to `internal/hidbridge/kernel/uhid`. Go's internal-path
rule then limits importers to `internal/hidbridge/kernel/...`.

1. `git mv internal/uhid internal/hidbridge/kernel/uhid`.
2. Update the imports in `internal/hidbridge/kernel/device.go` and
   `device_test.go`.
3. Check the package docs still read well (`uhid` stays the package name).

Pure move, no behaviour change.

## Done when

- `go build ./...` and `go test ./...` pass.
- `grep -rn '"llavero/internal/uhid"'` finds nothing.
