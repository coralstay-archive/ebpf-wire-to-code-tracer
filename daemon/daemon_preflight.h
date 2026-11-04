/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ==============================================================================
 * daemon/daemon_preflight.h — Privilege, Kernel BTF, Cgroups v2 & ELF Checks
 * ==============================================================================
 * Reference Check:
 * - Pre-flight privilege verification: Michael Kerrisk TLPI Chapter 38 (Capabilities)
 * - sysexits status codes: <sysexits.h> EX_NOPERM (77) & EX_UNAVAILABLE (69)
 * - BTF availability: references/rocky9.8-kernel-5.14.0-687.10.1.el9_8.0.1/
 * - Cgroups v2 memory limits: README.md#section-5
 * ==============================================================================
 */
#ifndef KRAY_DAEMON_PREFLIGHT_H
#define KRAY_DAEMON_PREFLIGHT_H

#include "daemon_types.h"

static int check_system_prerequisites(bool json_output)
{
    /* 1. Check Root Privileges or CAP_BPF */
    if (geteuid() != 0) {
        if (json_output) {
            fprintf(stderr, "{\"error\":\"EPERM\",\"message\":\"tracer_daemon requires root privileges or CAP_BPF/CAP_NET_ADMIN\"}\n");
        } else {
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, " [-] CRITICAL PRE-FLIGHT ERROR: Insufficient Privileges (geteuid=%d)\n", geteuid());
            fprintf(stderr, "     eBPF telemetry collection requires CAP_BPF, CAP_NET_ADMIN, and CAP_PERFMON.\n");
            fprintf(stderr, " [!] Remediation Options:\n");
            fprintf(stderr, "     1. Run with sudo:       sudo krayctl trace\n");
            fprintf(stderr, "     2. Grant Capabilities: sudo setcap cap_bpf,cap_net_admin,cap_sys_admin+ep /usr/local/bin/tracer_daemon\n");
            fprintf(stderr, "================================================================================\n");
        }
        return -EPERM;
    }

    /* 2. Check BTF vmlinux Availability */
    if (access("/sys/kernel/btf/vmlinux", R_OK) != 0) {
        if (json_output) {
            fprintf(stderr, "{\"error\":\"ENOENT\",\"message\":\"Kernel BTF (/sys/kernel/btf/vmlinux) not found\"}\n");
        } else {
            fprintf(stderr, "================================================================================\n");
            fprintf(stderr, " [-] CRITICAL PRE-FLIGHT ERROR: Missing Kernel BTF (/sys/kernel/btf/vmlinux)\n");
            fprintf(stderr, "     eBPF CO-RE requires kernel BTF type information enabled.\n");
            fprintf(stderr, " [!] Remediation Options:\n");
            fprintf(stderr, "     1. Verify kernel config: zcat /proc/config.gz | grep CONFIG_DEBUG_INFO_BTF\n");
            fprintf(stderr, "     2. Upgrade to a modern kernel (Rocky Linux 9.8 5.14.0+ supports BTF natively)\n");
            fprintf(stderr, "================================================================================\n");
        }
        return -ENOENT;
    }

    /* 3. Check BPF Filesystem Mount */
    if (access("/sys/fs/bpf", F_OK) != 0) {
        if (json_output) {
            fprintf(stderr, "{\"warning\":\"ENODEV\",\"message\":\"BPF filesystem /sys/fs/bpf not found\"}\n");
        } else {
            fprintf(stderr, " [!] WARNING: /sys/fs/bpf is not accessible. Pinning maps may fail.\n");
            fprintf(stderr, "     Remediation: sudo mount -t bpf bpf /sys/fs/bpf\n");
        }
    }

    /* 4. Check Cgroups v2 Memory Headroom Guard (< 64MB) */
    const char *cgroup_max_path = "/sys/fs/cgroup/memory.max";
    const char *cgroup_cur_path = "/sys/fs/cgroup/memory.current";
    if (access(cgroup_max_path, R_OK) == 0 && access(cgroup_cur_path, R_OK) == 0) {
        char max_buf[64] = {0};
        char cur_buf[64] = {0};
        int max_fd = open(cgroup_max_path, O_RDONLY);
        int cur_fd = open(cgroup_cur_path, O_RDONLY);
        if (max_fd >= 0 && cur_fd >= 0) {
            ssize_t max_bytes_read = read(max_fd, max_buf, sizeof(max_buf) - 1);
            ssize_t cur_bytes_read = read(cur_fd, cur_buf, sizeof(cur_buf) - 1);
            if (max_bytes_read > 0 && cur_bytes_read > 0) {
                while (max_bytes_read > 0 && (max_buf[max_bytes_read - 1] == '\n' || max_buf[max_bytes_read - 1] == ' ' || max_buf[max_bytes_read - 1] == '\r'))
                    max_buf[--max_bytes_read] = '\0';
                while (cur_bytes_read > 0 && (cur_buf[cur_bytes_read - 1] == '\n' || cur_buf[cur_bytes_read - 1] == ' ' || cur_buf[cur_bytes_read - 1] == '\r'))
                    cur_buf[--cur_bytes_read] = '\0';

                if (strcmp(max_buf, "max") != 0) {
                    uint64_t max_bytes = strtoull(max_buf, NULL, 10);
                    uint64_t cur_bytes = strtoull(cur_buf, NULL, 10);
                    uint64_t headroom = (max_bytes > cur_bytes) ? (max_bytes - cur_bytes) : 0;
                    const uint64_t threshold_64mb = 64ULL * 1024ULL * 1024ULL;

                    if (headroom < threshold_64mb) {
                        s_cgroup_low_headroom = true;
                        if (json_output) {
                            fprintf(stderr, "{\"warning\":\"LOW_CGROUP_MEMORY\",\"headroom_mb\":%llu,\"current_mb\":%llu,\"max_mb\":%llu}\n",
                                    (unsigned long long)(headroom / (1024 * 1024)),
                                    (unsigned long long)(cur_bytes / (1024 * 1024)),
                                    (unsigned long long)(max_bytes / (1024 * 1024)));
                        } else {
                            fprintf(stderr, "================================================================================\n");
                            fprintf(stderr, " [!] WARNING: Cgroups v2 Memory Headroom is critically low (< 64MB)!\n");
                            fprintf(stderr, "     Available Headroom: %llu MB (Current: %llu MB, Max Limit: %llu MB)\n",
                                    (unsigned long long)(headroom / (1024 * 1024)),
                                    (unsigned long long)(cur_bytes / (1024 * 1024)),
                                    (unsigned long long)(max_bytes / (1024 * 1024)));
                            fprintf(stderr, "     Risk: Container OOM-killer may terminate daemon during BPF map allocation.\n");
                            fprintf(stderr, " [!] Remediation: Increase container memory limit (e.g. docker run -m 512m).\n");
                            fprintf(stderr, "================================================================================\n");
                        }
                    }
                }
            }
        }
        if (max_fd >= 0) close(max_fd);
        if (cur_fd >= 0) close(cur_fd);
    }

    return 0;
}

static bool check_elf_stripped(const char *path)
{
#ifdef __linux__
    if (!path || access(path, R_OK) != 0)
        return false;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return false;

    int fd = open(path, O_RDONLY);
    if (fd < 0) return false;

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) { close(fd); return false; }

    bool has_symtab = false;
    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    while ((scn = elf_nextscn(e, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != NULL) {
            if (shdr.sh_type == SHT_SYMTAB) {
                has_symtab = true;
                break;
            }
        }
    }
    elf_end(e);
    close(fd);
    return !has_symtab;
#else
    (void)path;
    return false;
#endif
}

/*
 * Production ELF Symbol & Dynamic Symbol (.symtab + .dynsym) Auto-Resolver:
 * Resolves a human function name (exact C/Rust/Go name or C++ mangled substring)
 * into a precise instruction file offset for Uprobe/Uretprobe attachment, working
 * seamlessly even on stripped production shared libraries (.so) via SHT_DYNSYM.
 */
static bool resolve_elf_symbol_offset(
    const char *path,
    const char *symbol_name,
    uint64_t *out_offset,
    char *resolved_name,
    size_t name_len,
    const char **out_table_name)
{
#ifdef __linux__
    if (!path || !symbol_name || !out_offset || access(path, R_OK) != 0)
        return false;

    if (elf_version(EV_CURRENT) == EV_NONE)
        return false;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return false;

    Elf *e = elf_begin(fd, ELF_C_READ, NULL);
    if (!e) {
        close(fd);
        return false;
    }

    bool found_exact = false;
    bool found_fuzzy = false;
    uint64_t best_offset = 0;

    Elf_Scn *scn = NULL;
    GElf_Shdr shdr;
    while ((scn = elf_nextscn(e, scn)) != NULL && !found_exact) {
        if (gelf_getshdr(scn, &shdr) == NULL)
            continue;
        if (shdr.sh_type != SHT_SYMTAB && shdr.sh_type != SHT_DYNSYM)
            continue;
        if (shdr.sh_entsize == 0)
            continue;

        Elf_Data *data = elf_getdata(scn, NULL);
        if (!data)
            continue;

        size_t num_syms = shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < num_syms; i++) {
            GElf_Sym sym;
            if (gelf_getsym(data, (int)i, &sym) == NULL)
                continue;
            if (sym.st_value == 0 || sym.st_shndx == SHN_UNDEF)
                continue;

            const char *sname = elf_strptr(e, shdr.sh_link, sym.st_name);
            if (!sname || sname[0] == '\0')
                continue;

            bool is_exact = (strcmp(sname, symbol_name) == 0);
            bool is_fuzzy = (!is_exact && GELF_ST_TYPE(sym.st_info) == STT_FUNC && strstr(sname, symbol_name) != NULL);

            if (is_exact || (is_fuzzy && !found_fuzzy)) {
                Elf_Scn *target_scn = elf_getscn(e, sym.st_shndx);
                GElf_Shdr target_shdr;
                uint64_t f_off = sym.st_value;
                if (target_scn && gelf_getshdr(target_scn, &target_shdr) != NULL) {
                    if (sym.st_value >= target_shdr.sh_addr)
                        f_off = sym.st_value - target_shdr.sh_addr + target_shdr.sh_offset;
                }
                best_offset = f_off;
                if (resolved_name && name_len > 0) {
                    snprintf(resolved_name, name_len, "%s", sname);
                }
                if (out_table_name) {
                    *out_table_name = (shdr.sh_type == SHT_SYMTAB) ? ".symtab" : ".dynsym";
                }
                if (is_exact) {
                    found_exact = true;
                    break;
                }
                found_fuzzy = true;
            }
        }
    }

    elf_end(e);
    close(fd);

    if (found_exact || found_fuzzy) {
        *out_offset = best_offset;
        return true;
    }
    return false;
#else
    (void)path;
    (void)symbol_name;
    (void)out_offset;
    (void)resolved_name;
    (void)name_len;
    (void)out_table_name;
    return false;
#endif
}

#endif /* KRAY_DAEMON_PREFLIGHT_H */
