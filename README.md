# PS5 SFlash Dumper

A PS5 payload that makes a verified backup of your console's serial flash (`/dev/sflash0`, 2 MB), decodes the most useful identifiers into a readable text file, and splits the dump into its individual partitions.

**Version:** 1.1.0
**Tested on:** Relapse / kernel exploit, FW 7.00 – 13.60
---

## Features

- Dumps `/dev/sflash0` **twice** and compares both dumps with **CRC32**, so you know the backup is not corrupted
- Reads the console serial number and stores everything in a folder named after it
- Writes `sflash0_info.txt` with decoded, human-readable console info
- Extracts known partitions into a `parts/` folder
- Saves to USB (`/mnt/usb0`) when writable, otherwise falls back to `/data`
- Shows progress as on-console notifications
- **Read-only:** the tool never writes to the flash

---

## Output layout

```
<USB or /data>/
└── <SERIAL>/
    ├── sflash0_dump1.bin
    ├── sflash0_dump2.bin
    ├── sflash0_info.txt
    └── parts/
        ├── active_slot.bin
        ├── mbr1.bin
        ├── mbr2.bin
        ├── emc_ipl_a.bin
        ├── emc_ipl_b.bin
        ├── usb_pdc_a.bin
        ├── usb_pdc_b.bin
        ├── unk_region.bin
        ├── nvs.bin
        └── reserved.bin
```

During the dump, files are written to a temporary `sflash_tmp/` folder. They are moved to the serial-named folder only after both dumps match.

### Partitions

| File | Offset | Size |
|---|---|---|
| `active_slot.bin` | `0x001000` | `0x001000` |
| `mbr1.bin` | `0x002000` | `0x001000` |
| `mbr2.bin` | `0x003000` | `0x001000` |
| `emc_ipl_a.bin` | `0x004000` | `0x07E000` |
| `emc_ipl_b.bin` | `0x082000` | `0x07E000` |
| `usb_pdc_a.bin` | `0x100000` | `0x010000` |
| `usb_pdc_b.bin` | `0x110000` | `0x010000` |
| `unk_region.bin` | `0x120000` | `0x0A4000` |
| `nvs.bin` | `0x1C4000` | `0x00C000` |
| `reserved.bin` | `0x1D0000` | `0x030000` |

### Decoded info (`sflash0_info.txt`)

Board ID / motherboard type, model (SKU), model variant, region, serial number, motherboard SN, Kiban ID, SoC UID, LAN / WiFi MAC, Bluetooth addresses, image/PKG ID, active slot, IDU mode, and factory / minimum / current firmware versions.

Offsets come from the PS5 DevWiki and ps5-wee-tools.

---

## Usage

1. *(Optional)* Plug in a USB drive formatted as exFAT or FAT32. If `/mnt/usb0` is not writable, the dump goes to `/data`.
2. Jailbreak your console with a compatible exploit.
3. Send `sflash_dump.elf` to your payload loader (default port `9021`).
4. Wait for the notifications:
   - `Make Dump 1...`
   - `Make Dump 2...`
   - `Verifying backup...`
   - `Backup MATCHED (CRC OK)`
   - `Info TXT saved`
   - `Parts extracted OK`
5. Copy the `<SERIAL>` folder to a safe place, ideally to more than one.

If you see **`Backup NOT matched!`**, the two dumps differ. Do not trust them. Reboot and run it again.

---

## Building

Requires the [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk).

```sh
export PS5_PAYLOAD_SDK=/opt/ps5-payload-sdk
make
```

Example `Makefile`:

```make
PS5_HOST ?= ps5
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS := -Wall
ELF    := sflash_dump.elf

all: $(ELF)

$(ELF): sflash_dump.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(ELF)

test: $(ELF)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $^
```

Send it to the console with:

```sh
make test PS5_HOST=<console-ip>
```

---

## How it works

1. Escalates privileges (root, unjailed, extended authid and capabilities) through the SDK's kernel API
2. Opens `/dev/sflash0` and checks that its size is `0x200000`
3. Dumps the device twice in 64 KB blocks, aligned to 512-byte sectors
4. Compares size and CRC32 of both dumps
5. Reads the serial number at `0x1C7210` and sanitizes it into a folder name (falls back to `UNKNOWN`)
6. Moves the dumps, writes `sflash0_info.txt` and extracts the partitions

---

## Privacy notice

The dumps and `sflash0_info.txt` contain **console-unique identifiers**: serial number, MAC addresses, SoC UID, Kiban ID and more. **Never upload them publicly** (GitHub issues, Discord, forums), and redact them from screenshots and logs.

---

## Disclaimer

This tool is provided for backup and personal research purposes on hardware you own, **as is and without any warranty**. Use it at your own risk. The author is not responsible for any damage, data loss or bans resulting from its use.

---

## Credits

- [ps5-payload-dev/sdk](https://github.com/ps5-payload-dev/sdk)
- earthonion for inspiration
- PS5 DevWiki and ps5-wee-tools for the NVS offsets and partition layout
- The PS5 jailbreak / exploit community

## License

This project is open source and licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
