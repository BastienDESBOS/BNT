/*
 * IEC 61850-9-2 / 61869-9 SV sender over raw Ethernet (ethertype 0x88ba).
 * Format: Ethernet [dst|src|0x88ba] + SV payload (8-byte header + savPdu, 2 ASDUs).
 *
 * Dérivé de insatomcat/po (svgenerator/rt_sender.c). Ajout BNT : option
 * --format 4i4u|6i3u pour choisir le dataset SV émis (le 6I3U d'origine, ou le
 * 4I4U = 4 courants + 4 tensions, requis par certains départs, ex. DEP1-4).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <math.h>

#ifndef ETH_P_61850_SV
#define ETH_P_61850_SV 0x88ba
#endif

#define SMP_PER_SEC   4800
#define PKT_PER_SEC   2400
#define NSEC_PER_SEC  1000000000ULL
#define STEP_NS       (NSEC_PER_SEC / SMP_PER_SEC)
#define SV_ID_LEN     20
#define SEQDATA_6I3U  72   /* 6 courants + 3 tensions */
#define SEQDATA_4I4U  64   /* 4 courants + 4 tensions (compat Wireshark/9-2LE) */
#define SEQDATA_LEN   SEQDATA_6I3U  /* défaut, surchargé par --format 4i4u */
#define BER_BUF_SIZE  512
#define ETH_HEADER_LEN 14     /* dst(6) + src(6) + ethertype(2) */
#define ETH_VLAN_TAG_LEN 4    /* 0x8100 + TCI (PCP 3b | DEI 1b | VID 12b) */
#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

/* 6I3U: 6 courants (INT32+IQ×4B) + 3 tensions (INT32+VQ×4B) = 72 octets. Facteurs I×1000, V×100. */
#define I_SCALE  1000
#define V_SCALE  100
#define QUALITY_GOOD 0       /* bits Validity 00 = Good */

static uint8_t frame_buf[BER_BUF_SIZE + ETH_HEADER_LEN + ETH_VLAN_TAG_LEN];
static uint8_t ber_buf[BER_BUF_SIZE];
static uint8_t asdu_tmp[256];
static size_t ber_len;

/* Format de seqData sélectionnable à l'exécution (BNT) : 6I3U (défaut) ou 4I4U.
 * g_seqdata_len = longueur encodée réelle ; les tableaux restent dimensionnés au max. */
static int    g_use_4i4u = 0;
static size_t g_seqdata_len = SEQDATA_6I3U;

static void ber_reset(void) {
    ber_len = 0;
}

static void ber_append(const void *data, size_t n) {
    if (ber_len + n > BER_BUF_SIZE)
        return;
    memcpy(ber_buf + ber_len, data, n);
    ber_len += n;
}

static void ber_append_tag_len(uint8_t tag, unsigned len) {
    uint8_t t[3];
    t[0] = tag;
    if (len < 128) {
        t[1] = (uint8_t)len;
        ber_append(t, 2);
    } else {
        t[1] = 0x81;
        t[2] = (uint8_t)len;
        ber_append(t, 3);
    }
}

static size_t ber_encode_asdu(uint8_t *out, size_t out_max,
                               const char *svid, uint16_t smpCnt, uint8_t smp_synch, uint32_t conf_rev,
                               const uint8_t *seqData) {
    size_t svid_len = strnlen(svid, SV_ID_LEN);
    if (svid_len == 0)
        svid_len = 1;

    unsigned asdu_inner = (unsigned)(2 + svid_len + 4 + 6 + 3 + 2 + g_seqdata_len);
    size_t n = 0;

#define EMIT(tag, len, ptr, sz) do { \
    uint8_t _t[] = { (tag), (uint8_t)(len) }; \
    if (n + 2 + (sz) > out_max) return 0; \
    memcpy(out + n, _t, 2); n += 2; \
    memcpy(out + n, (ptr), (sz)); n += (sz); \
} while (0)

    if (asdu_inner >= 128) {
        if (n + 3 > out_max) return 0;
        out[n++] = 0x30;
        out[n++] = 0x81;
        out[n++] = (uint8_t)asdu_inner;
    } else {
        if (n + 2 > out_max) return 0;
        out[n++] = 0x30;
        out[n++] = (uint8_t)asdu_inner;
    }

    if (n + 2 + svid_len > out_max) return 0;
    out[n++] = 0x80;
    out[n++] = (uint8_t)svid_len;
    memcpy(out + n, svid, svid_len);
    n += svid_len;

    uint16_t be16 = htons(smpCnt);
    EMIT(0x82, 2, &be16, 2);

    uint32_t be32 = htonl(conf_rev);
    EMIT(0x83, 4, &be32, 4);

    EMIT(0x85, 1, &smp_synch, 1);

    EMIT(0x87, (uint8_t)g_seqdata_len, seqData, g_seqdata_len);

#undef EMIT
    return n;
}

static size_t ber_build_sv_packet(const char *svid, uint16_t smpCnt0, uint16_t smpCnt1,
                                   uint8_t smp_synch, uint16_t appid, uint32_t conf_rev,
                                   const uint8_t *seqData0, const uint8_t *seqData1) {
    size_t n0 = ber_encode_asdu(asdu_tmp, sizeof(asdu_tmp), svid, smpCnt0, smp_synch, conf_rev, seqData0);
    size_t n1 = ber_encode_asdu(asdu_tmp + n0, sizeof(asdu_tmp) - n0, svid, smpCnt1, smp_synch, conf_rev, seqData1);
    size_t seq_len = n0 + n1;

    unsigned seq_tl_n = (seq_len < 128) ? 2u : 3u;
    size_t sav_content = 3 + seq_tl_n + seq_len;
    unsigned sav_tl_n = (sav_content < 128) ? 2u : 3u;
    size_t apdu_len = sav_tl_n + sav_content;

    ber_reset();

    /* Length = total message length (8-byte header + savPdu). Normal packet: 0x00D3=211, not savPdu seul (203). */
    size_t total_len = 8u + apdu_len;
    ber_buf[0] = (appid >> 8) & 0xFF;
    ber_buf[1] = appid & 0xFF;
    ber_buf[2] = (uint8_t)((total_len >> 8) & 0xFF);
    ber_buf[3] = (uint8_t)(total_len & 0xFF);
    memset(ber_buf + 4, 0, 4);
    ber_len = 8;

    ber_append_tag_len(0x60, (unsigned)sav_content);
    ber_append((uint8_t[]){ 0x80, 0x01, 0x02 }, 3);
    ber_append_tag_len(0xa2, (unsigned)seq_len);
    ber_append(asdu_tmp, seq_len);

    return ber_len;
}

static void ns_to_timespec(int64_t ns, struct timespec *t) {
    int64_t sec = ns / (int64_t)NSEC_PER_SEC;
    int64_t nsec = ns % (int64_t)NSEC_PER_SEC;
    if (nsec < 0) {
        nsec += (int64_t)NSEC_PER_SEC;
        sec--;
    }
    t->tv_sec = (time_t)sec;
    t->tv_nsec = (long)nsec;
}

/* Remplit seqData 6I3U avec des sinusoïdes (ou zéros si freq_hz<=0).
 * fault_active: si 1, phase A utilise fault_* ; B et C inchangés.
 * Ordre: Ia,Ib,Ic,Ires,In,Ih (6×8B) + Va,Vb,Vc (3×8B). Qualité=Good. */
static void fill_seqdata_6i3u(uint8_t *seqData, uint16_t smpCnt,
                               double freq_hz, double i_peak_a, double v_peak_v,
                               double phase_deg,
                               int fault_active, double fault_i, double fault_v, double fault_phase) {
    int32_t vals[9];
    uint32_t qual = QUALITY_GOOD;  /* big-endian */

    if (freq_hz <= 0.0) {
        memset(vals, 0, sizeof(vals));
    } else {
        double t = (double)smpCnt / (double)SMP_PER_SEC;
        double phase = 2.0 * M_PI * freq_hz * t;

        double ia_peak = fault_active ? fault_i : i_peak_a;
        double phase_i_a = fault_active ? (phase - fault_phase * M_PI / 180.0) : (phase - phase_deg * M_PI / 180.0);
        double ia = ia_peak * sin(phase_i_a);

        double phase_i_bc = phase - phase_deg * M_PI / 180.0;
        double ib = i_peak_a * sin(phase_i_bc - 2.0 * M_PI / 3.0);
        double ic = i_peak_a * sin(phase_i_bc - 4.0 * M_PI / 3.0);

        vals[0] = (int32_t)round(ia * I_SCALE);
        vals[1] = (int32_t)round(ib * I_SCALE);
        vals[2] = (int32_t)round(ic * I_SCALE);
        vals[3] = (int32_t)round((ia + ib + ic) * I_SCALE);  /* Ires */
        vals[4] = 0;  /* In */
        vals[5] = 0;  /* Ih */

        double va_peak = fault_active ? fault_v : v_peak_v;
        double va = va_peak * sin(phase);
        double vb = v_peak_v * sin(phase - 2.0 * M_PI / 3.0);
        double vc = v_peak_v * sin(phase - 4.0 * M_PI / 3.0);

        vals[6] = (int32_t)round(va * V_SCALE);
        vals[7] = (int32_t)round(vb * V_SCALE);
        vals[8] = (int32_t)round(vc * V_SCALE);
    }

    size_t off = 0;
    for (int i = 0; i < 9; i++) {
        uint32_t be = htonl((uint32_t)vals[i]);
        memcpy(seqData + off, &be, 4);
        off += 4;
        memcpy(seqData + off, &qual, 4);  /* qual déjà en big-endian (0) */
        off += 4;
    }
}

/* Remplit seqData 4I4U (compat IEC 61850-9-2 LE) : 4 courants Ia,Ib,Ic,In puis
 * 4 tensions Va,Vb,Vc,Vn (8 voies × 8B = 64 octets). In et Vn = résiduels (sommes),
 * ~0 en régime équilibré, non nuls en défaut. Mêmes facteurs I×1000, V×100. */
static void fill_seqdata_4i4u(uint8_t *seqData, uint16_t smpCnt,
                               double freq_hz, double i_peak_a, double v_peak_v,
                               double phase_deg,
                               int fault_active, double fault_i, double fault_v, double fault_phase) {
    int32_t vals[8];
    uint32_t qual = QUALITY_GOOD;

    if (freq_hz <= 0.0) {
        memset(vals, 0, sizeof(vals));
    } else {
        double t = (double)smpCnt / (double)SMP_PER_SEC;
        double phase = 2.0 * M_PI * freq_hz * t;

        double ia_peak = fault_active ? fault_i : i_peak_a;
        double phase_i_a = fault_active ? (phase - fault_phase * M_PI / 180.0) : (phase - phase_deg * M_PI / 180.0);
        double ia = ia_peak * sin(phase_i_a);

        double phase_i_bc = phase - phase_deg * M_PI / 180.0;
        double ib = i_peak_a * sin(phase_i_bc - 2.0 * M_PI / 3.0);
        double ic = i_peak_a * sin(phase_i_bc - 4.0 * M_PI / 3.0);

        double va_peak = fault_active ? fault_v : v_peak_v;
        double va = va_peak * sin(phase);
        double vb = v_peak_v * sin(phase - 2.0 * M_PI / 3.0);
        double vc = v_peak_v * sin(phase - 4.0 * M_PI / 3.0);

        vals[0] = (int32_t)round(ia * I_SCALE);
        vals[1] = (int32_t)round(ib * I_SCALE);
        vals[2] = (int32_t)round(ic * I_SCALE);
        vals[3] = (int32_t)round((ia + ib + ic) * I_SCALE);   /* In résiduel */
        vals[4] = (int32_t)round(va * V_SCALE);
        vals[5] = (int32_t)round(vb * V_SCALE);
        vals[6] = (int32_t)round(vc * V_SCALE);
        vals[7] = (int32_t)round((va + vb + vc) * V_SCALE);   /* Vn résiduel */
    }

    size_t off = 0;
    for (int i = 0; i < 8; i++) {
        uint32_t be = htonl((uint32_t)vals[i]);
        memcpy(seqData + off, &be, 4);
        off += 4;
        memcpy(seqData + off, &qual, 4);
        off += 4;
    }
}

/* Aiguillage selon le format choisi (--format). */
static void fill_seqdata(uint8_t *seqData, uint16_t smpCnt,
                         double freq_hz, double i_peak_a, double v_peak_v, double phase_deg,
                         int fault_active, double fault_i, double fault_v, double fault_phase) {
    if (g_use_4i4u)
        fill_seqdata_4i4u(seqData, smpCnt, freq_hz, i_peak_a, v_peak_v, phase_deg,
                          fault_active, fault_i, fault_v, fault_phase);
    else
        fill_seqdata_6i3u(seqData, smpCnt, freq_hz, i_peak_a, v_peak_v, phase_deg,
                          fault_active, fault_i, fault_v, fault_phase);
}

/* Parse "aa:bb:cc:dd:ee:ff" into 6 bytes. Returns 0 on success. */
static int parse_mac(const char *str, uint8_t *mac) {
    unsigned int u[6];
    if (sscanf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
               &u[0], &u[1], &u[2], &u[3], &u[4], &u[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)u[i];
    return 0;
}

int main(int argc, char **argv) {
    uint8_t smp_synch = 0; /* 0=None, 1=Local, 2=Global. Défaut 0. */
    double freq_hz = 50.0;  /* fréquence sinusoïde (0 = tout à zéro) */
    double i_peak_a = 10.0; /* crête courant (A) */
    double v_peak_v = 100.0; /* crête tension (V) phase */
    double phase_deg = 0.0; /* déphasage I/V en degrés (>0 = courant en retard) */
    int fault_mode = 0;     /* 1 = mode défaut phase A alterné */
    double fault_i = 0.0, fault_v = 0.0, fault_phase = 0.0;
    double fault_cycle = 1.0; /* secondes par demi-cycle (1s normal, 1s fault) */
    int vlan_id = -1;       /* -1 = pas de VLAN; 0-4095 = VLAN tagué */
    int vlan_priority = 0;  /* PCP 0-7, utilisé si vlan_id >= 0 */
    uint16_t appid = 0;       /* APPID 0-65535 (0x0000-0xFFFF), obligatoire */
    uint32_t conf_rev = 0;    /* confRev 0-4294967295, obligatoire */
    int appid_set = 0;
    int conf_rev_set = 0;
    int dump_one = 0;       /* --dump: afficher 1er paquet hex et quitter */
    int debug_sync = 0;     /* --debug-sync: afficher durée du sleep à chaque seconde */
    const char *ifname = NULL;
    const char *src_mac_str = NULL;
    const char *dst_mac_str = NULL;
    const char *svid = NULL;
    int npos = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--smp-synch") == 0 && i + 1 < argc) {
            int v = atoi(argv[++i]);
            if (v < 0) v = 0;
            if (v > 2) v = 2;
            smp_synch = (uint8_t)v;
            continue;
        }
        if (strcmp(argv[i], "--freq") == 0 && i + 1 < argc) {
            freq_hz = atof(argv[++i]);
            if (freq_hz < 0) freq_hz = 0;
            continue;
        }
        if (strcmp(argv[i], "--zero") == 0) {
            freq_hz = 0;
            continue;
        }
        if (strcmp(argv[i], "--i-peak") == 0 && i + 1 < argc) {
            i_peak_a = atof(argv[++i]);
            if (i_peak_a < 0) i_peak_a = 0;
            continue;
        }
        if (strcmp(argv[i], "--v-peak") == 0 && i + 1 < argc) {
            v_peak_v = atof(argv[++i]);
            if (v_peak_v < 0) v_peak_v = 0;
            continue;
        }
        if (strcmp(argv[i], "--phase") == 0 && i + 1 < argc) {
            phase_deg = atof(argv[++i]);
            continue;
        }
        if (strcmp(argv[i], "--fault") == 0) {
            fault_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--fault-i-peak") == 0 && i + 1 < argc) {
            fault_i = atof(argv[++i]);
            if (fault_i < 0) fault_i = 0;
            fault_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--fault-v-peak") == 0 && i + 1 < argc) {
            fault_v = atof(argv[++i]);
            if (fault_v < 0) fault_v = 0;
            fault_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--fault-phase") == 0 && i + 1 < argc) {
            fault_phase = atof(argv[++i]);
            fault_mode = 1;
            continue;
        }
        if (strcmp(argv[i], "--fault-cycle") == 0 && i + 1 < argc) {
            fault_cycle = atof(argv[++i]);
            if (fault_cycle <= 0) fault_cycle = 1.0;
            continue;
        }
        if (strcmp(argv[i], "--vlan-id") == 0 && i + 1 < argc) {
            vlan_id = atoi(argv[++i]);
            if (vlan_id < 0) vlan_id = 0;
            if (vlan_id > 4095) vlan_id = 4095;
            continue;
        }
        if (strcmp(argv[i], "--vlan-priority") == 0 && i + 1 < argc) {
            vlan_priority = atoi(argv[++i]);
            if (vlan_priority < 0) vlan_priority = 0;
            if (vlan_priority > 7) vlan_priority = 7;
            continue;
        }
        if (strcmp(argv[i], "--appid") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 0); /* accepte decimal et 0x.... */
            if (end == argv[i] || (end && *end != '\0')) {
                fprintf(stderr, "Invalid --appid value: %s\n", argv[i]);
                return 1;
            }
            if (v > 0xFFFFUL)
                v = 0xFFFFUL;
            appid = (uint16_t)v;
            appid_set = 1;
            continue;
        }
        if (strcmp(argv[i], "--conf-rev") == 0 && i + 1 < argc) {
            char *end = NULL;
            unsigned long v = strtoul(argv[++i], &end, 0); /* accepte decimal et 0x.... */
            if (end == argv[i] || (end && *end != '\0')) {
                fprintf(stderr, "Invalid --conf-rev value: %s\n", argv[i]);
                return 1;
            }
            conf_rev = (uint32_t)v;
            conf_rev_set = 1;
            continue;
        }
        if (strcmp(argv[i], "--debug-sync") == 0) {
            debug_sync = 1;
            continue;
        }
        if (strcmp(argv[i], "--dump") == 0) {
            dump_one = 1;
            continue;
        }
        if (strcmp(argv[i], "--format") == 0 && i + 1 < argc) {
            const char *f = argv[++i];
            if (strcmp(f, "4i4u") == 0) {
                g_use_4i4u = 1;
                g_seqdata_len = SEQDATA_4I4U;
            } else if (strcmp(f, "6i3u") == 0) {
                g_use_4i4u = 0;
                g_seqdata_len = SEQDATA_6I3U;
            } else {
                fprintf(stderr, "Invalid --format value (4i4u|6i3u): %s\n", f);
                return 1;
            }
            continue;
        }
        if (npos == 0) ifname = argv[i];
        else if (npos == 1) src_mac_str = argv[i];
        else if (npos == 2) dst_mac_str = argv[i];
        else if (npos == 3) svid = argv[i];
        npos++;
    }

    if (npos != 4 || !ifname || !src_mac_str || !dst_mac_str || !svid || !*svid || !appid_set || !conf_rev_set) {
        fprintf(stderr, "Usage: %s [opts] <interface> <src_mac> <dst_mac> <svid>\n", argv[0]);
        fprintf(stderr, "  opts: --smp-synch 0|1|2  --freq Hz  --zero  --i-peak A  --v-peak V  --phase deg\n");
        fprintf(stderr, "        --fault  --fault-i-peak A  --fault-v-peak V  --fault-phase deg  --fault-cycle s\n");
        fprintf(stderr, "        --vlan-id <0-4095>  --vlan-priority <0-7>  (défaut: pas de VLAN)\n");
        fprintf(stderr, "        --appid <0-65535|0x0000-0xFFFF>  (obligatoire)\n");
        fprintf(stderr, "        --conf-rev <0-4294967295|0x00000000-0xFFFFFFFF>  (obligatoire)\n");
        fprintf(stderr, "        --format 4i4u|6i3u  (défaut 6i3u ; 4i4u = 4 courants + 4 tensions, 64 octets)\n");
        fprintf(stderr, "  smpSynch: 0=None, 1=Local, 2=Global. freq: 50 par défaut (0=zéros).\n");
        fprintf(stderr, "  e.g. %s --freq 50 lo 00:00:00:00:00:01 00:00:00:00:00:02 LDTM1_SVI_DEP6\n", argv[0]);
        fprintf(stderr, "  --dump: build 1 packet, print hex to stderr, exit (no send).\n");
        fprintf(stderr, "  --debug-sync: afficher durée du sleep (µs) à chaque seconde.\n");
        return 1;
    }

    uint8_t src_mac[ETH_ALEN];
    if (parse_mac(src_mac_str, src_mac) != 0) {
        fprintf(stderr, "Invalid src_mac (use aa:bb:cc:dd:ee:ff)\n");
        return 1;
    }

    uint8_t dest_mac[ETH_ALEN];
    if (parse_mac(dst_mac_str, dest_mac) != 0) {
        fprintf(stderr, "Invalid dst_mac (use aa:bb:cc:dd:ee:ff)\n");
        return 1;
    }

    if (dump_one) {
        uint8_t seq0[SEQDATA_LEN], seq1[SEQDATA_LEN];
        memset(seq0, 0, sizeof(seq0));
        memset(seq1, 0, sizeof(seq1));
        fill_seqdata(seq0, 0, freq_hz, i_peak_a, v_peak_v, phase_deg, 0, fault_i, fault_v, fault_phase);
        fill_seqdata(seq1, 1, freq_hz, i_peak_a, v_peak_v, phase_deg, 0, fault_i, fault_v, fault_phase);
        size_t plen = ber_build_sv_packet(svid, 0, 1, smp_synch, appid, conf_rev, seq0, seq1);
        fprintf(stderr, "Built: %s %s\n", __DATE__, __TIME__);
        fprintf(stderr, "SV payload %zu bytes. Length@2-3=0x%02x%02x (big-endian). Hex:\n",
                plen, ber_buf[2], ber_buf[3]);
        for (size_t i = 0; i < plen; i += 16) {
            fprintf(stderr, "  %04zx:", i);
            for (size_t j = i; j < i + 16 && j < plen; j++)
                fprintf(stderr, " %02x", ber_buf[j]);
            fprintf(stderr, "\n");
        }
        return 0;
    }

    int ifindex = (int)if_nametoindex(ifname);
    if (ifindex == 0) {
        fprintf(stderr, "Unknown interface: %s\n", ifname);
        return 1;
    }

    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        perror("mlockall");

    struct sched_param sp;
    memset(&sp, 0, sizeof(sp));
    sp.sched_priority = 80;
    if (sched_setscheduler(0, SCHED_FIFO, &sp) != 0)
        perror("sched_setscheduler");

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket AF_PACKET");
        return 1;
    }

    /* Mettre l'interface UP (nécessaire pour OVS bridge/internal port souvent DOWN) */
    {
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
        ifr.ifr_name[IFNAMSIZ - 1] = '\0';
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (!(ifr.ifr_flags & IFF_UP)) {
                ifr.ifr_flags |= IFF_UP;
                if (ioctl(sock, SIOCSIFFLAGS, &ifr) != 0) {
                    perror("ioctl SIOCSIFFLAGS (bring interface up)");
                    fprintf(stderr, "Hint: run 'ip link set %s up' as root, or use a tap port on the OVS bridge.\n", ifname);
                } else {
                    fprintf(stderr, "Interface %s brought up (was down, required for OVS bridge/internal port).\n", ifname);
                }
            }
        } else {
            perror("ioctl SIOCGIFFLAGS");
        }
    }

    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifindex;
    addr.sll_halen = ETH_ALEN;
    memcpy(addr.sll_addr, dest_mac, ETH_ALEN);

    struct timespec rt_now;
    if (clock_gettime(CLOCK_REALTIME, &rt_now) != 0) {
        perror("clock_gettime REALTIME");
        close(sock);
        return 1;
    }

    time_t start_wall_sec = rt_now.tv_sec + 1;
    const uint64_t step_ns = NSEC_PER_SEC / PKT_PER_SEC;

    fprintf(stderr, "Built: %s %s\n", __DATE__, __TIME__);
    fprintf(stderr, "Starting at next wall-clock second: %ld, svID=\"%s\", 2 ASDU/pkt, %u pkt/s\n",
            (long)start_wall_sec, svid, (unsigned)PKT_PER_SEC);
    if (vlan_id >= 0)
        fprintf(stderr, "Ethernet: iface %s, src %s, dst %s, VLAN %d prio %d, ethertype 0x88ba\n",
                ifname, src_mac_str, dst_mac_str, vlan_id, vlan_priority);
    else
        fprintf(stderr, "Ethernet: iface %s, src %s, dst %s, ethertype 0x88ba (pas de VLAN)\n",
                ifname, src_mac_str, dst_mac_str);
    fprintf(stderr, "Clock: CLOCK_REALTIME (PTP-friendly). smpSynch=%u (0=None,1=Local,2=Global). Sync: sleep until boundary each second.\n",
            (unsigned)smp_synch);
    fprintf(stderr, "APPID: 0x%04x (%u)\n", (unsigned)appid, (unsigned)appid);
    fprintf(stderr, "confRev: %u\n", (unsigned)conf_rev);
    fprintf(stderr, "Format: %s (%zu octets de seqData)\n",
            g_use_4i4u ? "4I4U (Ia,Ib,Ic,In,Va,Vb,Vc,Vn)" : "6I3U (Ia,Ib,Ic,Ires,In,Ih,Va,Vb,Vc)",
            g_seqdata_len);
    if (freq_hz > 0) {
        fprintf(stderr, "6I3U: sinusoïdes %.1f Hz, I_peak=%.1f A, V_peak=%.1f V, déphasage=%.1f° (facteurs I×%d, V×%d).\n",
                freq_hz, i_peak_a, v_peak_v, phase_deg, I_SCALE, V_SCALE);
        if (fault_mode)
            fprintf(stderr, "Fault: phase A I=%.1f A V=%.1f V phase=%.1f°, cycle=%.1fs (%.1fs normal, %.1fs fault).\n",
                    fault_i, fault_v, fault_phase, fault_cycle, fault_cycle, fault_cycle);
    } else
        fprintf(stderr, "6I3U: toutes valeurs à zéro (--zero ou --freq 0).\n");

    uint8_t seqData0[SEQDATA_LEN], seqData1[SEQDATA_LEN];

    uint64_t sec_index = 0;

    for (;;) {
        /* Attendre la borne nominale: smpCnt 0 part toujours à la seconde pile. */
        int64_t boundary_ns = (int64_t)(start_wall_sec + (time_t)sec_index) * (int64_t)NSEC_PER_SEC;
        struct timespec target;
        struct timespec now_ts;
        int64_t sleep_ns = 0;
        if (debug_sync && clock_gettime(CLOCK_REALTIME, &now_ts) == 0) {
            int64_t now_ns = (int64_t)now_ts.tv_sec * (int64_t)NSEC_PER_SEC + (int64_t)now_ts.tv_nsec;
            sleep_ns = boundary_ns - now_ns;
        }
        ns_to_timespec(boundary_ns, &target);
        int ret;
        do {
            ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &target, NULL);
        } while (ret == EINTR);
        if (ret != 0)
            perror("clock_nanosleep");
        if (debug_sync)
            fprintf(stderr, "[sync] sec=%lu sleep=%lld µs\n", (unsigned long)sec_index, (long long)(sleep_ns / 1000));

        int64_t second_start_ns = boundary_ns;

        for (uint32_t k = 0; k < PKT_PER_SEC; k++) {
            int64_t target_ns = second_start_ns + (int64_t)(k * step_ns);
            ns_to_timespec(target_ns, &target);
            do {
                ret = clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &target, NULL);
            } while (ret == EINTR);
            if (ret != 0)
                perror("clock_nanosleep");

            /* fault_cycle: (sec_index % (2*cycle)) >= cycle => fault */
            int in_fault = fault_mode && (double)(sec_index % (uint64_t)(2.0 * fault_cycle + 0.5)) >= fault_cycle;
            fill_seqdata(seqData0, (uint16_t)(k * 2), freq_hz, i_peak_a, v_peak_v, phase_deg,
                         in_fault, fault_i, fault_v, fault_phase);
            fill_seqdata(seqData1, (uint16_t)(k * 2 + 1), freq_hz, i_peak_a, v_peak_v, phase_deg,
                         in_fault, fault_i, fault_v, fault_phase);
            size_t payload_len = ber_build_sv_packet(svid, (uint16_t)(k * 2), (uint16_t)(k * 2 + 1),
                                                     smp_synch, appid, conf_rev, seqData0, seqData1);

            size_t hdr_len;
            memcpy(frame_buf, dest_mac, ETH_ALEN);
            memcpy(frame_buf + ETH_ALEN, src_mac, ETH_ALEN);
            if (vlan_id >= 0) {
                uint16_t tci = (uint16_t)((vlan_priority & 7) << 13) | (uint16_t)(vlan_id & 0xFFF);
                frame_buf[12] = (ETH_P_8021Q >> 8) & 0xFF;
                frame_buf[13] = ETH_P_8021Q & 0xFF;
                frame_buf[14] = (tci >> 8) & 0xFF;
                frame_buf[15] = tci & 0xFF;
                frame_buf[16] = (ETH_P_61850_SV >> 8) & 0xFF;
                frame_buf[17] = ETH_P_61850_SV & 0xFF;
                memcpy(frame_buf + 18, ber_buf, payload_len);
                hdr_len = 18;
            } else {
                frame_buf[12] = (ETH_P_61850_SV >> 8) & 0xFF;
                frame_buf[13] = ETH_P_61850_SV & 0xFF;
                memcpy(frame_buf + ETH_HEADER_LEN, ber_buf, payload_len);
                hdr_len = ETH_HEADER_LEN;
            }

            ssize_t sent = sendto(sock, frame_buf, hdr_len + payload_len, 0,
                                  (struct sockaddr *)&addr, sizeof(addr));
            if (sent < 0)
                perror("sendto");
        }

        /* Après le dernier paquet, on est ~416 µs avant la borne suivante. On dort jusqu'à
         * la borne : la durée s'adapte (400 µs, 416 µs, 430 µs...) selon l'avance/retard. */
        sec_index++;
    }

    close(sock);
    return 0;
}
