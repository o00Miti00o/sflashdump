// sflash_dump.c — PS5 SFlash dual dump + CRC32 + human-readable info + parts
// Version: 1.1.0
// SDK:    https://github.com/ps5-payload-dev/sdk
// Tested: Relapse / kernel exploit (FW 7.00 – 13.60)
//
// Flow:
//   1. Escalate privileges (root + authid)
//   2. Dump /dev/sflash0 twice into a temp folder
//   3. Compare both dumps with CRC32
//   4. Read serial from dump1 → create <USB|/data>/<SERIAL>/
//   5. Move dumps, write sflash0_info.txt, extract partitions to parts/

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <ps5/kernel.h>

/* -------------------------------------------------------------------- */
/* Paths and sizes                                                      */
/* -------------------------------------------------------------------- */
#define SFLASH_DEV     "/dev/sflash0"
#define SFLASH0_SIZE   0x200000
#define BLOCK_SIZE     0x200
#define BUFSZ          0x10000

#define BASE_USB       "/mnt/usb0"
#define BASE_DATA      "/data"
#define TMP_DIRNAME    "sflash_tmp"

/* NVS offsets — PS5 DevWiki / ps5-wee-tools NOR_AREAS */
#define OFF_BOARD_ID     0x1C4000
#define OFF_LAN_MAC      0x1C4020
#define OFF_MODEL_VAR    0x1C7011
#define OFF_ACTIVE_SLOT  0x001000
#define OFF_MB_SN        0x1C7200
#define OFF_SERIAL       0x1C7210
#define OFF_SKU          0x1C7230
#define OFF_REGION       0x1C7236
#define OFF_KIBAN        0x1C7250
#define OFF_SOCUID       0x1C7260
#define OFF_WIFI_MAC     0x1C73C0
#define OFF_BD_ADDR1     0x1C73C6
#define OFF_BD_ADDR2     0x1C73CC
#define OFF_IMAGE_ID     0x1C73E0
#define OFF_FW_MINIMUM   0x1C8C10
#define OFF_FW_FACTORY   0x1C8C20
#define OFF_FW_CURRENT   0x1C8C30
#define OFF_IDU_MODE     0x1C9600

/* -------------------------------------------------------------------- */
/* Console notifications                                                */
/* -------------------------------------------------------------------- */
typedef struct {
    int  type;
    int  req_id;
    int  priority;
    int  msg_id;
    int  target_id;
    int  user_id;
    int  unk1;
    int  unk2;
    int  app_id;
    int  error_num;
    int  unk3;
    char use_icon_image_uri;
    char message[1024];
    char uri[1024];
    char unkstr[1024];
} SceNotificationRequest;

int sceKernelSendNotificationRequest(int, SceNotificationRequest *, size_t, int);

static void notify(const char *fmt, ...)
{
    SceNotificationRequest req;
    memset(&req, 0, sizeof(req));
    req.type               = 0;
    req.unk3               = 0;
    req.use_icon_image_uri = 1;
    req.target_id          = -1;
    snprintf(req.uri, sizeof(req.uri),
             "cxml://psnotification/tex_icon_system");

    __builtin_va_list ap;
    __builtin_va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    __builtin_va_end(ap);

    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

/* -------------------------------------------------------------------- */
/* CRC32 (IEEE)                                                         */
/* -------------------------------------------------------------------- */
static uint32_t crc32_table[256];
static int      crc32_ready = 0;

static void crc32_init(void)
{
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32_file(const char *path, uint64_t *out_size)
{
    if (!crc32_ready)
        crc32_init();

    int fd = open(path, O_RDONLY, 0);
    if (fd < 0)
        return 0;

    static uint8_t buf[BUFSZ];
    uint32_t crc = 0xFFFFFFFFu;
    uint64_t total = 0;
    ssize_t n;

    while ((n = read(fd, buf, BUFSZ)) > 0) {
        for (ssize_t i = 0; i < n; i++)
            crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
        total += (uint64_t)n;
    }
    close(fd);

    if (out_size)
        *out_size = total;

    return crc ^ 0xFFFFFFFFu;
}

/* -------------------------------------------------------------------- */
/* Jailbreak                                                            */
/* -------------------------------------------------------------------- */
static int jailbreak(void)
{
    pid_t pid = getpid();

    static const uint8_t caps[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    intptr_t root_vnode = kernel_get_root_vnode();
    if (!root_vnode) {
        printf("[!] kernel_get_root_vnode() failed\n");
        return -1;
    }

    if (kernel_set_proc_rootdir(pid, root_vnode)) return -1;
    if (kernel_set_proc_jaildir(pid, root_vnode)) return -1;
    if (kernel_set_ucred_uid(pid, 0))   return -1;
    if (kernel_set_ucred_ruid(pid, 0))  return -1;
    if (kernel_set_ucred_svuid(pid, 0)) return -1;
    if (kernel_set_ucred_rgid(pid, 0))  return -1;

    if (kernel_set_ucred_authid(pid, 0x4801000000000013ULL)) {
        printf("[!] kernel_set_ucred_authid() failed\n");
        return -1;
    }
    if (kernel_set_ucred_caps(pid, caps)) {
        printf("[!] kernel_set_ucred_caps() failed\n");
        return -1;
    }
    return 0;
}

/* -------------------------------------------------------------------- */
/* Helpers                                                              */
/* -------------------------------------------------------------------- */
static int read_at(int fd, off_t off, void *buf, size_t n)
{
    if (lseek(fd, off, SEEK_SET) < 0)
        return -1;
    return (read(fd, buf, n) == (ssize_t)n) ? 0 : -1;
}

static void ascii_clean(char *dst, size_t dstsz, const uint8_t *src, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; i < n && j + 1 < dstsz; i++) {
        unsigned char c = src[i];
        if (c == 0x00 || c == 0xFF)
            break;
        if (c >= 32 && c < 127)
            dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

static void sanitize_folder_name(char *dst, size_t dstsz, const char *src)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dstsz; i++) {
        char c = src[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '_' || c == '-') {
            dst[j++] = c;
        }
    }
    dst[j] = '\0';
    if (j == 0)
        snprintf(dst, dstsz, "UNKNOWN");
}

static int dir_writable(const char *path)
{
    char test[512];
    snprintf(test, sizeof(test), "%s/.sflash_write_test", path);
    int fd = open(test, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0)
        return 0;
    close(fd);
    unlink(test);
    return 1;
}

static int move_file(const char *src, const char *dst)
{
    if (rename(src, dst) == 0)
        return 0;

    int in = open(src, O_RDONLY, 0);
    if (in < 0)
        return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        close(in);
        return -1;
    }

    static uint8_t buf[BUFSZ];
    ssize_t n;
    while ((n = read(in, buf, BUFSZ)) > 0) {
        if (write(out, buf, (size_t)n) != n) {
            close(in);
            close(out);
            return -1;
        }
    }
    fsync(out);
    close(out);
    close(in);
    unlink(src);
    return 0;
}

static int extract_serial_from_dump(const char *dump_path,
                                    char *folder_out, size_t folder_sz)
{
    int fd = open(dump_path, O_RDONLY, 0);
    if (fd < 0)
        return -1;

    uint8_t raw[32];
    char ascii[40];
    memset(raw, 0, sizeof(raw));

    if (read_at(fd, OFF_SERIAL, raw, sizeof(raw)) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    ascii_clean(ascii, sizeof(ascii), raw, sizeof(raw));
    sanitize_folder_name(folder_out, folder_sz, ascii);
    return 0;
}

static void hex_bytes(char *dst, size_t dstsz, const uint8_t *src, size_t n)
{
    size_t pos = 0;
    for (size_t i = 0; i < n && pos + 3 < dstsz; i++) {
        pos += (size_t)snprintf(dst + pos, dstsz - pos, "%02X%s",
                                src[i], (i + 1 < n) ? ":" : "");
    }
    if (pos < dstsz)
        dst[pos] = '\0';
}

/* Compact SoC UID: AABBCC... (no colons) */
static void fmt_soc_uid(char *dst, size_t dstsz, const uint8_t *src, size_t n)
{
    size_t pos = 0;
    for (size_t i = 0; i < n && pos + 2 < dstsz; i++)
        pos += (size_t)snprintf(dst + pos, dstsz - pos, "%02X", src[i]);
    if (pos < dstsz)
        dst[pos] = '\0';
}

static void fmt_fw(char *dst, size_t dstsz, const uint8_t *b)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | b[i];

    if (v == 0) {
        snprintf(dst, dstsz, "N/A");
        return;
    }

    uint32_t hi  = (uint32_t)(v >> 32);
    unsigned maj = (hi >> 24) & 0xFF;
    unsigned min = (hi >> 16) & 0xFF;
    snprintf(dst, dstsz, "%02X.%02X", maj, min);
}

static void fmt_board_id(char *dst, size_t dstsz, const uint8_t *b)
{
    const char *bd =
        (b[5] == 0x01) ? "Yes" :
        (b[5] == 0x03) ? "No"  : "?";
    const char *typ = (b[1] == 0x02) ? "Retail" : "Non-Retail";

    snprintf(dst, dstsz,
             "EDM-0%dX BD:%s %s [%02X:%02X:%02X:%02X:%02X:%02X:%02X:%02X]",
             (int)b[2], bd, typ,
             b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
}

static void fmt_region(char *dst, size_t dstsz, const char *code2)
{
    if (!code2[0] || !code2[1]) {
        snprintf(dst, dstsz, "N/A");
        return;
    }
    if (!strcmp(code2, "00"))
        snprintf(dst, dstsz, "[%s] Japan", code2);
    else if (!strcmp(code2, "01") || !strcmp(code2, "15"))
        snprintf(dst, dstsz, "[%s] US / Canada (North America)", code2);
    else if (!strcmp(code2, "02"))
        snprintf(dst, dstsz, "[%s] Australia / New Zealand", code2);
    else if (!strcmp(code2, "03"))
        snprintf(dst, dstsz, "[%s] UK / Ireland", code2);
    else if (!strcmp(code2, "04") || !strcmp(code2, "16"))
        snprintf(dst, dstsz, "[%s] Europe / Middle East / Africa", code2);
    else if (!strcmp(code2, "05") || !strcmp(code2, "18"))
        snprintf(dst, dstsz, "[%s] Korea / Singapore / Asia", code2);
    else if (!strcmp(code2, "06"))
        snprintf(dst, dstsz, "[%s] Southeast Asia / Hong Kong", code2);
    else if (!strcmp(code2, "07"))
        snprintf(dst, dstsz, "[%s] Taiwan", code2);
    else if (!strcmp(code2, "08"))
        snprintf(dst, dstsz, "[%s] Russia / Ukraine / India / Central Asia", code2);
    else if (!strcmp(code2, "09"))
        snprintf(dst, dstsz, "[%s] Mainland China", code2);
    else if (!strcmp(code2, "11") || !strcmp(code2, "14"))
        snprintf(dst, dstsz, "[%s] Mexico / Central & South America", code2);
    else
        snprintf(dst, dstsz, "[%s] Unknown", code2);
}

static const char *model_variant_name(uint8_t v)
{
    switch (v) {
    case 0x01: return "Slim edition";
    case 0x02: return "Disc edition";
    case 0x03: return "Digital edition";
    default:   return "Unknown";
    }
}

/* -------------------------------------------------------------------- */
/* Dump                                                                 */
/* -------------------------------------------------------------------- */
static off_t blk_align_down(off_t x)
{
    return x & ~(off_t)(BLOCK_SIZE - 1);
}

static int do_one_dump(int sflash_fd, off_t dump_size, const char *out_path)
{
    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        printf("[!] cannot create %s: %s\n", out_path, strerror(errno));
        return -1;
    }

    if (lseek(sflash_fd, 0, SEEK_SET) < 0) {
        printf("[!] lseek failed: %s\n", strerror(errno));
        close(out);
        return -1;
    }

    static uint8_t buf[BUFSZ];
    uint64_t total = 0;

    while ((off_t)total < dump_size) {
        size_t to_read = BUFSZ;
        if ((off_t)(total + to_read) > dump_size)
            to_read = (size_t)(dump_size - (off_t)total);

        to_read = (size_t)blk_align_down((off_t)to_read);
        if (to_read == 0)
            to_read = BLOCK_SIZE;

        ssize_t n = read(sflash_fd, buf, to_read);
        if (n < 0) {
            printf("[!] read error at 0x%llx: %s\n",
                   (unsigned long long)total, strerror(errno));
            close(out);
            return -1;
        }
        if (n == 0)
            break;

        if (write(out, buf, (size_t)n) != n) {
            printf("[!] write error at 0x%llx\n", (unsigned long long)total);
            close(out);
            return -1;
        }
        total += (uint64_t)n;
    }

    fsync(out);
    close(out);

    if (total != (uint64_t)dump_size) {
        printf("[!] incomplete dump: %llu / %llu\n",
               (unsigned long long)total, (unsigned long long)dump_size);
        return -1;
    }

    printf("[+] OK %s (%llu KB)\n",
           out_path, (unsigned long long)(total / 1024));
    return 0;
}

/* -------------------------------------------------------------------- */
/* sflash0_info.txt                                                     */
/* -------------------------------------------------------------------- */
static int write_info_txt(const char *dump_path, const char *txt_path)
{
    int fd = open(dump_path, O_RDONLY, 0);
    if (fd < 0) {
        printf("[!] open for parse %s: %s\n", dump_path, strerror(errno));
        return -1;
    }

    uint8_t board[8], soc[16], lan[6], mac[6], bd1[6], bd2[6], img[8];
    uint8_t mb_sn[16], serial[24], sku[16], kiban[16];
    uint8_t fw_min[8], fw_fac[8], fw_cur[8];
    uint8_t slot = 0xFF, idu = 0xFF, model_var = 0xFF;
    char region2[4];

    memset(board, 0, sizeof(board));
    memset(soc, 0, sizeof(soc));
    memset(lan, 0, sizeof(lan));
    memset(mac, 0, sizeof(mac));
    memset(bd1, 0, sizeof(bd1));
    memset(bd2, 0, sizeof(bd2));
    memset(img, 0, sizeof(img));
    memset(mb_sn, 0, sizeof(mb_sn));
    memset(serial, 0, sizeof(serial));
    memset(sku, 0, sizeof(sku));
    memset(kiban, 0, sizeof(kiban));
    memset(fw_min, 0, sizeof(fw_min));
    memset(fw_fac, 0, sizeof(fw_fac));
    memset(fw_cur, 0, sizeof(fw_cur));
    memset(region2, 0, sizeof(region2));

    read_at(fd, OFF_BOARD_ID,    board,   sizeof(board));
    read_at(fd, OFF_LAN_MAC,     lan,     6);
    read_at(fd, OFF_MODEL_VAR,   &model_var, 1);
    read_at(fd, OFF_ACTIVE_SLOT, &slot,   1);
    read_at(fd, OFF_MB_SN,       mb_sn,   sizeof(mb_sn));
    read_at(fd, OFF_SERIAL,      serial,  sizeof(serial));
    read_at(fd, OFF_SKU,         sku,     sizeof(sku));
    read_at(fd, OFF_REGION,      region2, 2);
    read_at(fd, OFF_KIBAN,       kiban,   sizeof(kiban));
    read_at(fd, OFF_SOCUID,      soc,     sizeof(soc));
    read_at(fd, OFF_WIFI_MAC,    mac,     6);
    read_at(fd, OFF_BD_ADDR1,    bd1,     6);
    read_at(fd, OFF_BD_ADDR2,    bd2,     6);
    read_at(fd, OFF_IMAGE_ID,    img,     8);
    read_at(fd, OFF_FW_MINIMUM,  fw_min,  8);
    read_at(fd, OFF_FW_FACTORY,  fw_fac,  8);
    read_at(fd, OFF_FW_CURRENT,  fw_cur,  8);
    read_at(fd, OFF_IDU_MODE,    &idu,    1);
    close(fd);

    char s_mobo[96], s_serial[40], s_mbsn[40], s_sku[40], s_kiban[40];
    char s_img[24], s_region[96], s_soc[40];
    char s_lan[24], s_mac[24], s_bd1[24], s_bd2[24];
    char s_min[16], s_fac[16], s_cur[16];
    char region_code[4];

    fmt_board_id(s_mobo, sizeof(s_mobo), board);

    ascii_clean(s_serial, sizeof(s_serial), serial, sizeof(serial));
    ascii_clean(s_mbsn,   sizeof(s_mbsn),   mb_sn,  sizeof(mb_sn));
    ascii_clean(s_sku,    sizeof(s_sku),    sku,    sizeof(sku));
    ascii_clean(s_kiban,  sizeof(s_kiban),  kiban,  sizeof(kiban));
    ascii_clean(s_img,    sizeof(s_img),    img,    sizeof(img));
    if (s_img[0] == '\0')
        snprintf(s_img, sizeof(s_img), "N/A");

    region_code[0] = (region2[0] >= '0' && region2[0] <= '9') ? region2[0] : 0;
    region_code[1] = (region2[1] >= '0' && region2[1] <= '9') ? region2[1] : 0;
    region_code[2] = 0;
    if (!region_code[0] && strlen(s_sku) >= 8) {
        region_code[0] = s_sku[6];
        region_code[1] = s_sku[7];
        region_code[2] = 0;
    }
    fmt_region(s_region, sizeof(s_region), region_code);

    fmt_soc_uid(s_soc, sizeof(s_soc), soc, 16);
    hex_bytes(s_lan, sizeof(s_lan), lan, 6);
    hex_bytes(s_mac, sizeof(s_mac), mac, 6);
    hex_bytes(s_bd1, sizeof(s_bd1), bd1, 6);
    hex_bytes(s_bd2, sizeof(s_bd2), bd2, 6);

    fmt_fw(s_min, sizeof(s_min), fw_min);
    fmt_fw(s_fac, sizeof(s_fac), fw_fac);
    fmt_fw(s_cur, sizeof(s_cur), fw_cur);

    const char *slot_name =
        (slot == 0x00) ? "A" :
        (slot == 0x80) ? "B" : "?";

    const char *idu_str =
        (idu == 0x01) ? "ON" :
        (idu == 0x00 || idu == 0xFF) ? "OFF" : "UNKNOWN";

    const char *mvar = model_variant_name(model_var);

    int out = open(txt_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        printf("[!] cannot create %s: %s\n", txt_path, strerror(errno));
        return -1;
    }

    char line[640];
    int n;
#define W(fmt, ...) do { \
        n = snprintf(line, sizeof(line), fmt "\n", ##__VA_ARGS__); \
        if (n > 0) write(out, line, (size_t)n); \
    } while (0)

    W("PS5 SFlash info");
    W("Source dump : %s", dump_path);
    W("----------------------------------------");
    W("Mobo [Board ID] : %s", s_mobo);
    W("Model (SKU)     : %s", s_sku);
    W("Model variant   : %s (0x%02X)", mvar, model_var);
    W("Region          : %s", s_region);
    W("Serial          : %s", s_serial);
    W("Mobo SN         : %s", s_mbsn);
    W("Kiban ID        : %s", s_kiban);
    W("SoC UID         : %s", s_soc);
    W("MAC LAN         : %s", s_lan);
    W("MAC WiFi        : %s", s_mac);
    W("BD Addr 1       : %s", s_bd1);
    W("BD Addr 2       : %s", s_bd2);
    W("Image/PKG       : %s", s_img);
    W("Active slot     : 0x%02X (%s)", slot, slot_name);
    W("IDU mode        : %s (0x%02X)", idu_str, idu);
    W("Factory FW      : %s", s_fac);
    W("Minimum FW      : %s", s_min);
    W("Current FW      : %s", s_cur);
    W("----------------------------------------");
    W("Decoded with offsets from PS5 DevWiki / ps5-wee-tools");
#undef W

    fsync(out);
    close(out);

    printf("[+] Info written -> %s\n", txt_path);
    printf("    %s\n", s_mobo);
    printf("    SKU: %s | Serial: %s | Kiban: %s | PKG: %s | FW: %s\n",
           s_sku, s_serial, s_kiban, s_img, s_cur);
    return 0;
}

/* -------------------------------------------------------------------- */
/* Partition extract → parts/                                           */
/* -------------------------------------------------------------------- */
typedef struct {
    const char *name;
    off_t       off;
    size_t      size;
} PartEnt;

static const PartEnt g_parts[] = {
    { "active_slot.bin", 0x001000, 0x001000 },
    { "mbr1.bin",        0x002000, 0x001000 },
    { "mbr2.bin",        0x003000, 0x001000 },
    { "emc_ipl_a.bin",   0x004000, 0x07E000 },
    { "emc_ipl_b.bin",   0x082000, 0x07E000 },
    { "usb_pdc_a.bin",   0x100000, 0x010000 },
    { "usb_pdc_b.bin",   0x110000, 0x010000 },
    { "unk_region.bin",  0x120000, 0x0A4000 },
    { "nvs.bin",         0x1C4000, 0x00C000 },
    { "reserved.bin",    0x1D0000, 0x030000 },
};

static int extract_part(int infd, const char *out_path, off_t off, size_t size)
{
    if (lseek(infd, off, SEEK_SET) < 0)
        return -1;

    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0)
        return -1;

    static uint8_t buf[BUFSZ];
    size_t left = size;
    while (left > 0) {
        size_t chunk = left > BUFSZ ? BUFSZ : left;
        ssize_t n = read(infd, buf, chunk);
        if (n <= 0) {
            close(out);
            return -1;
        }
        if (write(out, buf, (size_t)n) != n) {
            close(out);
            return -1;
        }
        left -= (size_t)n;
    }
    fsync(out);
    close(out);
    return 0;
}

static int extract_inner_files(const char *dump_path, const char *parts_dir)
{
    if (mkdir(parts_dir, 0777) < 0 && errno != EEXIST) {
        printf("[!] mkdir %s: %s\n", parts_dir, strerror(errno));
        return -1;
    }

    int infd = open(dump_path, O_RDONLY, 0);
    if (infd < 0) {
        printf("[!] open dump for extract: %s\n", strerror(errno));
        return -1;
    }

    int ok = 0, fail = 0;
    char out_path[600];

    for (size_t i = 0; i < sizeof(g_parts) / sizeof(g_parts[0]); i++) {
        snprintf(out_path, sizeof(out_path), "%s/%s",
                 parts_dir, g_parts[i].name);
        if (extract_part(infd, out_path, g_parts[i].off, g_parts[i].size) == 0) {
            printf("[+] extracted %s\n", g_parts[i].name);
            ok++;
        } else {
            printf("[!] failed %s\n", g_parts[i].name);
            fail++;
        }
    }
    close(infd);

    printf("[+] Extract: %d ok, %d failed -> %s\n", ok, fail, parts_dir);
    return (fail == 0) ? 0 : -1;
}

/* -------------------------------------------------------------------- */
/* main                                                                 */
/* -------------------------------------------------------------------- */
int main(void)
{
    printf("\n=== PS5 SFLASH DUMPER x2 + CRC + INFO + PARTS (v1.1.0) ===\n\n");

    printf("[*] Jailbreak...\n");
    if (jailbreak() < 0) {
        notify("sflash: jailbreak failed");
        return 1;
    }

    printf("[+] Privileges OK (uid=%d, authid=0x%lx)\n",
           (int)kernel_get_ucred_uid(getpid()),
           (unsigned long)kernel_get_ucred_authid(getpid()));

    {
        int t = open(SFLASH_DEV, O_RDONLY | O_NONBLOCK, 0);
        if (t < 0) {
            printf("[!] %s not accessible: %s (errno=%d)\n",
                   SFLASH_DEV, strerror(errno), errno);
            notify("sflash: access denied — %s", strerror(errno));
            return 1;
        }
        close(t);
    }
    printf("[+] %s accessible\n", SFLASH_DEV);

    int fd = open(SFLASH_DEV, O_RDONLY, 0);
    if (fd < 0) {
        printf("[!] open failed: %s (errno=%d)\n", strerror(errno), errno);
        notify("sflash: open failed");
        return 1;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz != (off_t)SFLASH0_SIZE) {
        printf("[!] unexpected size: 0x%lx (expected 0x%x)\n",
               (unsigned long)sz, SFLASH0_SIZE);
    } else {
        printf("[+] Size: 0x%x (%d MB)\n",
               SFLASH0_SIZE, SFLASH0_SIZE / 1024 / 1024);
    }
    off_t dump_size = (sz > 0) ? sz : (off_t)SFLASH0_SIZE;

    const char *base = BASE_USB;
    if (!dir_writable(BASE_USB)) {
        printf("[!] USB not writable, using /data/\n");
        mkdir(BASE_DATA, 0777);
        base = BASE_DATA;
    }

    char tmp_dir[512];
    snprintf(tmp_dir, sizeof(tmp_dir), "%s/%s", base, TMP_DIRNAME);
    if (mkdir(tmp_dir, 0777) < 0 && errno != EEXIST) {
        printf("[!] mkdir %s failed: %s\n", tmp_dir, strerror(errno));
        notify("sflash: cannot create temp folder");
        close(fd);
        return 1;
    }

    char path1[540], path2[540];
    snprintf(path1, sizeof(path1), "%s/sflash0_dump1.bin", tmp_dir);
    snprintf(path2, sizeof(path2), "%s/sflash0_dump2.bin", tmp_dir);

    printf("[*] Make Dump 1...\n");
    notify("Make Dump 1...");
    if (do_one_dump(fd, dump_size, path1) < 0) {
        notify("sflash: Dump 1 FAILED");
        close(fd);
        return 1;
    }

    printf("[*] Make Dump 2...\n");
    notify("Make Dump 2...");
    if (do_one_dump(fd, dump_size, path2) < 0) {
        notify("sflash: Dump 2 FAILED");
        close(fd);
        return 1;
    }
    close(fd);

    printf("[*] Verifying backup...\n");
    notify("Verifying backup...");

    uint64_t size1 = 0, size2 = 0;
    uint32_t crc1 = crc32_file(path1, &size1);
    uint32_t crc2 = crc32_file(path2, &size2);

    printf("[+] Dump1: size=%llu  CRC32=0x%08X\n",
           (unsigned long long)size1, crc1);
    printf("[+] Dump2: size=%llu  CRC32=0x%08X\n",
           (unsigned long long)size2, crc2);

    if (!(size1 == size2 && size1 == (uint64_t)dump_size && crc1 == crc2)) {
        printf("[!] NOT MATCHED\n");
        notify("Backup NOT matched!");
        return 1;
    }

    printf("[+] MATCHED — dumps are identical\n");
    notify("Backup MATCHED (CRC OK)");

    printf("[*] Parsing serial...\n");
    notify("Parsing dump info...");

    char folder_name[64];
    if (extract_serial_from_dump(path1, folder_name, sizeof(folder_name)) < 0) {
        printf("[!] serial unknown, using UNKNOWN\n");
        snprintf(folder_name, sizeof(folder_name), "UNKNOWN");
    }
    printf("[+] Serial folder: %s\n", folder_name);

    char final_dir[512];
    snprintf(final_dir, sizeof(final_dir), "%s/%s", base, folder_name);
    if (mkdir(final_dir, 0777) < 0 && errno != EEXIST) {
        printf("[!] mkdir %s failed: %s\n", final_dir, strerror(errno));
        notify("sflash: cannot create serial folder");
        return 1;
    }

    char final1[540], final2[540], info_path[540];
    snprintf(final1, sizeof(final1), "%s/sflash0_dump1.bin", final_dir);
    snprintf(final2, sizeof(final2), "%s/sflash0_dump2.bin", final_dir);
    snprintf(info_path, sizeof(info_path), "%s/sflash0_info.txt", final_dir);

    if (move_file(path1, final1) < 0 || move_file(path2, final2) < 0) {
        printf("[!] move failed\n");
        notify("sflash: move failed");
        return 1;
    }
    rmdir(tmp_dir);

    if (write_info_txt(final1, info_path) == 0)
        notify("Info TXT saved");
    else {
        notify("Info TXT failed");
        return 1;
    }

    char parts_dir[540];
    snprintf(parts_dir, sizeof(parts_dir), "%s/parts", final_dir);
    printf("[*] Extracting inner files...\n");
    notify("Extracting parts...");
    if (extract_inner_files(final1, parts_dir) == 0)
        notify("Parts extracted OK");
    else
        notify("Parts extract incomplete");

    printf("\n[+] Done. Folder: %s\n", final_dir);
    printf("    dumps + sflash0_info.txt + parts/\n");
    return 0;
}
