// sflash_dump.c — PS5 SFlash Full Dumper (2x + CRC verify)
// SDK:    https://github.com/ps5-payload-dev/sdk
// Testat: Relapse (FW 7.00 - 13.60) — inclusiv 12.40

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

/* ================================================================== */
/*  Constante                                                          */
/* ================================================================== */
#define SFLASH_DEV    "/dev/sflash0"
#define SFLASH0_SIZE  0x200000    /* 2 MB — fix pe PS5                */
#define BLOCK_SIZE    0x200       /* 512 B — aliniere obligatorie      */
#define BUFSZ         0x10000     /* 64 KB per citire (multiplu de 512)*/

#define OUT_USB1      "/mnt/usb0/sflash0_dump1.bin"
#define OUT_USB2      "/mnt/usb0/sflash0_dump2.bin"
#define OUT_DATA1     "/data/sflash0_dump1.bin"
#define OUT_DATA2     "/data/sflash0_dump2.bin"

/* ================================================================== */
/*  Notificari PS5                                                     */
/* ================================================================== */
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

int sceKernelSendNotificationRequest(int, SceNotificationRequest*, size_t, int);

static void notify(const char *fmt, ...) {
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

/* ================================================================== */
/*  CRC32 (IEEE)                                                       */
/* ================================================================== */
static uint32_t crc32_table[256];
static int      crc32_ready = 0;

static void crc32_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int j = 0; j < 8; j++)
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        crc32_table[i] = c;
    }
    crc32_ready = 1;
}

static uint32_t crc32_file(const char *path, uint64_t *out_size) {
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

/* ================================================================== */
/*  Jailbreak complet                                                  */
/* ================================================================== */
static int jailbreak(void) {
    pid_t pid = getpid();

    static const uint8_t caps[16] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    };

    intptr_t root_vnode = kernel_get_root_vnode();
    if (!root_vnode) {
        printf("[!] kernel_get_root_vnode() esuat\n");
        return -1;
    }

    if (kernel_set_proc_rootdir(pid, root_vnode)) {
        printf("[!] kernel_set_proc_rootdir() esuat\n");
        return -1;
    }
    if (kernel_set_proc_jaildir(pid, root_vnode)) {
        printf("[!] kernel_set_proc_jaildir() esuat\n");
        return -1;
    }

    if (kernel_set_ucred_uid(pid, 0)) {
        printf("[!] kernel_set_ucred_uid() esuat\n");
        return -1;
    }
    if (kernel_set_ucred_ruid(pid, 0)) {
        printf("[!] kernel_set_ucred_ruid() esuat\n");
        return -1;
    }
    if (kernel_set_ucred_svuid(pid, 0)) {
        printf("[!] kernel_set_ucred_svuid() esuat\n");
        return -1;
    }
    if (kernel_set_ucred_rgid(pid, 0)) {
        printf("[!] kernel_set_ucred_rgid() esuat\n");
        return -1;
    }

    if (kernel_set_ucred_authid(pid, 0x4801000000000013ULL)) {
        printf("[!] kernel_set_ucred_authid() esuat\n");
        return -1;
    }

    if (kernel_set_ucred_caps(pid, caps)) {
        printf("[!] kernel_set_ucred_caps() esuat\n");
        return -1;
    }

    return 0;
}

/* ================================================================== */
/*  Aliniere                                                           */
/* ================================================================== */
static off_t blk_align_down(off_t x) {
    return x & ~(off_t)(BLOCK_SIZE - 1);
}

/* ================================================================== */
/*  Un dump (fara progress 10%)                                        */
/* ================================================================== */
static int do_one_dump(int sflash_fd, off_t dump_size, const char *out_path) {
    int out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (out < 0) {
        printf("[!] Nu pot crea %s: %s\n", out_path, strerror(errno));
        return -1;
    }

    if (lseek(sflash_fd, 0, SEEK_SET) < 0) {
        printf("[!] lseek esuat: %s\n", strerror(errno));
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
            printf("[!] Eroare citire la 0x%llx: %s\n",
                   (unsigned long long)total, strerror(errno));
            close(out);
            return -1;
        }
        if (n == 0)
            break;

        if (write(out, buf, (size_t)n) != n) {
            printf("[!] Eroare scriere la 0x%llx\n",
                   (unsigned long long)total);
            close(out);
            return -1;
        }
        total += (uint64_t)n;
    }

    fsync(out);
    close(out);

    if (total != (uint64_t)dump_size) {
        printf("[!] Dump incomplet: %llu / %llu\n",
               (unsigned long long)total,
               (unsigned long long)dump_size);
        return -1;
    }

    printf("[+] OK %s (%llu KB)\n",
           out_path, (unsigned long long)(total / 1024));
    return 0;
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */
int main(void) {
    printf("\n=== PS5 SFLASH DUMPER x2 + CRC (12.40+) ===\n\n");

    /* ---- 1. Jailbreak -------------------------------------------- */
    printf("[*] Jailbreak...\n");
    if (jailbreak() < 0) {
        notify("sflash: jailbreak esuat");
        return 1;
    }

    printf("[+] Privilegii OK (uid=%d, authid=0x%lx)\n",
           (int)kernel_get_ucred_uid(getpid()),
           (unsigned long)kernel_get_ucred_authid(getpid()));

    /* ---- 2. Acces sflash ----------------------------------------- */
    {
        int t = open(SFLASH_DEV, O_RDONLY | O_NONBLOCK, 0);
        if (t < 0) {
            printf("[!] %s inaccesibil: %s (errno=%d)\n",
                   SFLASH_DEV, strerror(errno), errno);
            notify("sflash: acces refuzat — %s", strerror(errno));
            return 1;
        }
        close(t);
    }
    printf("[+] %s accesibil\n", SFLASH_DEV);

    /* ---- 3. Deschide sflash0 ------------------------------------- */
    int fd = open(SFLASH_DEV, O_RDONLY, 0);
    if (fd < 0) {
        printf("[!] open esuat: %s (errno=%d)\n", strerror(errno), errno);
        notify("sflash: open esuat");
        return 1;
    }

    off_t sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    if (sz != (off_t)SFLASH0_SIZE) {
        printf("[!] Dimensiune neasteptata: 0x%lx (asteptat 0x%x)\n",
               (unsigned long)sz, SFLASH0_SIZE);
    } else {
        printf("[+] Dimensiune: 0x%x (%d MB)\n",
               SFLASH0_SIZE, SFLASH0_SIZE / 1024 / 1024);
    }
    off_t dump_size = (sz > 0) ? sz : (off_t)SFLASH0_SIZE;

    /* ---- 4. Alege path-uri (USB sau /data) ----------------------- */
    const char *path1 = OUT_USB1;
    const char *path2 = OUT_USB2;
    {
        int test = open(OUT_USB1, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (test < 0) {
            printf("[!] USB indisponibil, folosesc /data/\n");
            mkdir("/data", 0777);
            path1 = OUT_DATA1;
            path2 = OUT_DATA2;
        } else {
            close(test);
            unlink(OUT_USB1); /* stergem testul, refacem in do_one_dump */
        }
    }

    /* ---- 5. Dump 1 ----------------------------------------------- */
    printf("[*] Make Dump 1...\n");
    notify("Make Dump 1...");
    if (do_one_dump(fd, dump_size, path1) < 0) {
        notify("sflash: Dump 1 ESUAT");
        close(fd);
        return 1;
    }

    /* ---- 6. Dump 2 ----------------------------------------------- */
    printf("[*] Make Dump 2...\n");
    notify("Make Dump 2...");
    if (do_one_dump(fd, dump_size, path2) < 0) {
        notify("sflash: Dump 2 ESUAT");
        close(fd);
        return 1;
    }
    close(fd);

    /* ---- 7. Verify CRC ------------------------------------------- */
    printf("[*] Verifying backup...\n");
    notify("Verifying backup...");

    uint64_t size1 = 0, size2 = 0;
    uint32_t crc1 = crc32_file(path1, &size1);
    uint32_t crc2 = crc32_file(path2, &size2);

    printf("[+] Dump1: %s  size=%llu  CRC32=0x%08X\n",
           path1, (unsigned long long)size1, crc1);
    printf("[+] Dump2: %s  size=%llu  CRC32=0x%08X\n",
           path2, (unsigned long long)size2, crc2);

    if (size1 == size2 && size1 == (uint64_t)dump_size && crc1 == crc2) {
        printf("[+] MATCHED — backup-uri identice\n");
        notify("Backup MATCHED (CRC OK)");
    } else {
        printf("[!] NOT MATCHED — size sau CRC diferit\n");
        notify("Backup NOT matched!");
        return 1;
    }

    return 0;
}