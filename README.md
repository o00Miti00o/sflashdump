# PS5 SFlash Dumper

Payload for jailbroken PlayStation 5 consoles that reads `/dev/sflash0` (NOR flash, ~2 MB), writes **two independent dumps**, and verifies they match with **CRC32**.

Tested with **Relapse** on firmware **12.40**

## Features

- Full dump of `/dev/sflash0` (2 MB, 512-byte aligned reads)
- Two consecutive dumps from the device
- CRC32 comparison of both files
- Console notifications: `Make Dump 1...` → `Make Dump 2...` → `Verifying backup...` → matched / not matched
- Output: USB (`/mnt/usb0/`) preferred, fallback to `/data/`
- Kernel privilege escalation (uid 0, authid, full caps, root vnode)
- **Read-only** — does not write to NOR

## Requirements

- Jailbroken PS5 with (FW 7.00–13.60)
- **kstuff-lite** loaded
- ELF loader on port **9021**
- Optional: USB drive formatted **exFAT**
- Build: [ps5-payload-sdk](https://github.com/ps5-payload-dev/sdk)

## Build

```bash
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make

Output: sflash_dump.elf

Run
Run Relapse
Load kstuff-lite
(Optional) Insert an exFAT USB drive
Send the payload:

bash
socat -t 30 TCP:PS5_IP:9021 < sflash_dump.elf
# or
nc PS5_IP 9021 < sflash_dump.elf

Output files
Location	Files
USB	/mnt/usb0/sflash0_dump1.bin, sflash0_dump2.bin
Fallback	/data/sflash0_dump1.bin, sflash0_dump2.bin
Expected size: 0x200000 (2 MB) each.

How it works
Jailbreak process (root vnode, uid 0, privileged authid, full capabilities)
Open /dev/sflash0 read-only
Dump 1 → file 1
Dump 2 → file 2
Compute CRC32 on both files
Notify MATCHED if size and CRC are identical, otherwise NOT matched
Two dumps + CRC reduce the chance of a silent read error.

Troubleshooting
Issue	Check
Access denied / errno 13	Is kstuff-lite loaded?
Jailbreak failed	Relapse + kstuff for your FW
Cannot write output	USB mounted (exFAT) or space under /data
NOT matched	Retry; do not remove USB during dump
Disclaimer
For personal backup and research on your own jailbroken console only.
Incorrect use of flash data can damage hardware. Use at your own risk.

Credits
ps5-payload-dev/sdk
Relapse / kstuff ecosystem
earthonion

-All PS5 developers-

License
MIT (or your choice — add a LICENSE file)
