# Packaging files

Reference copies of everything that has to be installed outside the binary.
Distro packages should use these rather than asking users to paste from the
top-level README.

| File | Install to |
|---|---|
| `llavero-uhid@.service` | `/usr/lib/systemd/system/` |
| `llavero-uhid` (build `./cmd/llavero-uhid`) | `/usr/lib/llavero/` |
| `70-tpmrm-uaccess.rules` | `/usr/lib/udev/rules.d/` (only needed for TPM unlock) |
| `llavero.service` | `/usr/lib/systemd/user/` |
| `user@.service.d-20-memlock.conf` | `/etc/systemd/system/user@.service.d/20-memlock.conf` |

Enable the system broker for each authorized numeric UID:
`sudo systemctl enable --now llavero-uhid@1000.service`.
It owns `/dev/uhid`; do not install a uaccess rule for that device.
The root-owned runtime directory contains a socket owned by that UID with mode
0600. Both peers check `SO_PEERCRED`. Only fixed-size FIDO reports cross IPC;
clients cannot choose HID descriptors or receive the UHID file descriptor.
Load the `uhid` kernel module before starting the service (or configure it in
`/etc/modules-load.d/`). The TPM udev rule is needed only for TPM unlock.

The `user@.service.d` drop-in raises the locked-memory ceiling. It is separate
because a user unit cannot raise a hard rlimit above the one the
`systemd --user` manager holds, so `LimitMEMLOCK` in `llavero.service` is
silently ignored without it. It also needs a reboot, since that manager
commonly survives a logout.
