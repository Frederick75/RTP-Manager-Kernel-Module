/*
 * rtp_app.c — User-space RTP streaming demo for RTP Manager kernel module
 *
 * Modes:
 *  - tx: generate RTP packets and send via UDP using mmap ring slots
 *  - rx: receive RTP packets via UDP and push into mmap ring slots
 *  - ctl: print stats
 *
 * Build: make -C user
 */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "../include/rtp_mgr_ioctl.h"

#define DEFAULT_DEV "/dev/rtp_mgr"
#define RTP_VERSION 2
#define RTP_PT_DYNAMIC 96

struct rtp_hdr {
    uint8_t vpxcc;
    uint8_t mpt;
    uint16_t seq;
    uint32_t ts;
    uint32_t ssrc;
} __attribute__((packed));

struct app_cfg {
    const char *dev;
    const char *mode;     /* tx|rx|ctl */
    const char *bind_ip;
    const char *dst_ip;
    int port;
    int rate_pps;
    int payload_size;
};

struct shared_layout {
    uint32_t ring_order;
    uint32_t ring_size;
    uint32_t slot_payload;
    uint32_t slot_stride;
    uint8_t *base;
    size_t len;
};

static atomic_bool g_stop = false;

static void on_sigint(int sig) {
    (void)sig;
    g_stop = true;
}

static uint64_t now_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + (uint64_t)tv.tv_usec;
}

static size_t calc_stride(uint32_t payload) {
    size_t stride = sizeof(struct rtpm_slot_desc) + payload;
    stride = (stride + 63) & ~(size_t)63;
    return stride;
}

static int open_dev(const char *dev) {
    int fd = open(dev, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "open(%s) failed: %s\n", dev, strerror(errno));
        return -1;
    }
    return fd;
}

static int get_cfg(int fd, struct rtpm_config *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    if (ioctl(fd, RTPM_IOCTL_GET_CONFIG, cfg) != 0) {
        fprintf(stderr, "ioctl(GET_CONFIG) failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}

static int start_mod(int fd) {
    if (ioctl(fd, RTPM_IOCTL_START) != 0) {
        fprintf(stderr, "ioctl(START) failed: %s\n", strerror(errno));
        return -1;
    }
    return 0;
}
static int stop_mod(int fd) {
    (void)ioctl(fd, RTPM_IOCTL_STOP);
    return 0;
}

static int map_shared(int fd, const struct rtpm_config *cfg, struct shared_layout *out) {
    uint32_t ring_size = 1u << cfg->ring_order;
    size_t stride = calc_stride(cfg->slot_payload);
    size_t total = (size_t)ring_size * stride;

    void *p = mmap(NULL, total, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) {
        fprintf(stderr, "mmap failed: %s\n", strerror(errno));
        return -1;
    }

    out->ring_order = cfg->ring_order;
    out->ring_size = ring_size;
    out->slot_payload = cfg->slot_payload;
    out->slot_stride = (uint32_t)stride;
    out->base = (uint8_t *)p;
    out->len = total;
    return 0;
}

static inline uint8_t *slot_ptr(const struct shared_layout *sh, uint32_t index) {
    return sh->base + (size_t)index * sh->slot_stride;
}
static inline struct rtpm_slot_desc *slot_desc(const struct shared_layout *sh, uint32_t index) {
    return (struct rtpm_slot_desc *)slot_ptr(sh, index);
}
static inline uint8_t *slot_payload_ptr(const struct shared_layout *sh, uint32_t index) {
    return slot_ptr(sh, index) + sizeof(struct rtpm_slot_desc);
}

static int udp_socket_bind(const char *ip, int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    int one = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = ip ? inet_addr(ip) : htonl(INADDR_ANY);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

static int udp_socket_connect(const char *ip, int port) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((uint16_t)port);
    addr.sin_addr.s_addr = inet_addr(ip);

    if (connect(s, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

/* RX thread: network -> mmap slot -> PUSH_SLOT */
struct rx_ctx {
    int devfd;
    int sock;
    struct shared_layout sh;
};

static void *rx_thread(void *arg) {
    struct rx_ctx *ctx = (struct rx_ctx *)arg;
    uint32_t idx = 0;
    uint8_t pkt[2048 + sizeof(struct rtp_hdr)];

    while (!g_stop) {
        ssize_t n = recv(ctx->sock, pkt, sizeof(pkt), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            fprintf(stderr, "recv: %s\n", strerror(errno));
            break;
        }
        if ((size_t)n < sizeof(struct rtp_hdr)) continue;

        struct rtp_hdr *rh = (struct rtp_hdr *)pkt;
        uint32_t payload_len = (uint32_t)(n - (ssize_t)sizeof(struct rtp_hdr));
        if (payload_len > ctx->sh.slot_payload) continue;

        /* Write payload into current index slot */
        struct rtpm_slot_desc *sd = slot_desc(&ctx->sh, idx);
        uint8_t *pl = slot_payload_ptr(&ctx->sh, idx);
        memcpy(pl, pkt + sizeof(struct rtp_hdr), payload_len);

        sd->index = idx;
        sd->payload_len = payload_len;
        sd->rtp_seq = ntohs(rh->seq);
        sd->rtp_ts  = ntohl(rh->ts);

        /* Notify kernel that slot is READY */
        if (ioctl(ctx->devfd, RTPM_IOCTL_PUSH_SLOT, sd) != 0) {
            if (errno != ENOSPC && errno != EINVAL) {
                fprintf(stderr, "PUSH_SLOT failed: %s\n", strerror(errno));
            }
            /* On ring full, drop packet and retry same idx */
        } else {
            idx = (idx + 1) & (ctx->sh.ring_size - 1);
        }
    }
    return NULL;
}

/* TX thread: POP_SLOT -> read mmap payload -> network send -> RELEASE_SLOT */
struct tx_ctx {
    int devfd;
    int sock;
    struct shared_layout sh;
    int rate_pps;
    uint32_t ssrc;
};

static void *tx_thread(void *arg) {
    struct tx_ctx *ctx = (struct tx_ctx *)arg;
    struct rtp_hdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.vpxcc = (uint8_t)(RTP_VERSION << 6);
    hdr.mpt = RTP_PT_DYNAMIC;

    uint16_t seq = 1;
    uint32_t ts = 0;

    uint64_t period_us = (ctx->rate_pps > 0) ? (1000000ULL / (uint64_t)ctx->rate_pps) : 20000ULL;

    while (!g_stop) {
        struct rtpm_slot_desc sd;
        memset(&sd, 0, sizeof(sd));

        if (ioctl(ctx->devfd, RTPM_IOCTL_POP_SLOT, &sd) != 0) {
            if (errno == EAGAIN) {
                /* no ready slot */
                usleep(1000);
                continue;
            }
            if (errno == EINTR) continue;
            fprintf(stderr, "POP_SLOT failed: %s\n", strerror(errno));
            break;
        }

        uint8_t *pl = slot_payload_ptr(&ctx->sh, sd.index);
        uint32_t payload_len = sd.payload_len;
        if (payload_len > ctx->sh.slot_payload) payload_len = ctx->sh.slot_payload;

        hdr.seq = htons(seq++);
        hdr.ts = htonl(ts);
        hdr.ssrc = htonl(ctx->ssrc);
        ts += 3000; /* demo increment */

        /* send RTP header + payload */
        uint8_t out[1500 + sizeof(struct rtp_hdr)];
        size_t send_len = sizeof(struct rtp_hdr) + payload_len;
        if (send_len > sizeof(out)) send_len = sizeof(out);

        memcpy(out, &hdr, sizeof(hdr));
        memcpy(out + sizeof(hdr), pl, send_len - sizeof(hdr));

        (void)send(ctx->sock, out, send_len, 0);

        /* release slot */
        if (ioctl(ctx->devfd, RTPM_IOCTL_RELEASE_SLOT, &sd) != 0) {
            fprintf(stderr, "RELEASE_SLOT failed: %s\n", strerror(errno));
        }

        usleep((useconds_t)period_us);
    }
    return NULL;
}

static int print_stats(int devfd) {
    struct rtpm_stats s;
    memset(&s, 0, sizeof(s));
    if (ioctl(devfd, RTPM_IOCTL_GET_STATS, &s) != 0) {
        fprintf(stderr, "GET_STATS failed: %s\n", strerror(errno));
        return -1;
    }
    printf("stats: pushed=%llu popped=%llu bytes_in=%llu bytes_out=%llu drops_full=%llu drops_noready=%llu\n",
           (unsigned long long)s.pkts_pushed,
           (unsigned long long)s.pkts_popped,
           (unsigned long long)s.bytes_pushed,
           (unsigned long long)s.bytes_popped,
           (unsigned long long)s.drops_ring_full,
           (unsigned long long)s.drops_no_ready);
    return 0;
}

static void usage(const char *p) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --mode rx --bind <ip> --port <p>\n"
        "  %s --mode tx --dst  <ip> --port <p> [--rate pps] [--payload bytes]\n"
        "  %s --mode ctl --stats\n\n"
        "Options:\n"
        "  --dev <path>        Device node (default /dev/rtp_mgr)\n"
        "  --mode <rx|tx|ctl>\n"
        "  --bind <ip>         Bind IP for rx (default 0.0.0.0)\n"
        "  --dst  <ip>         Destination IP for tx\n"
        "  --port <port>       UDP port (default 5004)\n"
        "  --rate <pps>        TX packets/sec (default 50)\n"
        "  --payload <bytes>   TX payload bytes written into mmap slots (default 1200)\n"
        "  --stats             Print stats (ctl)\n",
        p, p, p);
}

int main(int argc, char **argv) {
    struct app_cfg cfg = {
        .dev = DEFAULT_DEV,
        .mode = NULL,
        .bind_ip = NULL,
        .dst_ip = NULL,
        .port = 5004,
        .rate_pps = 50,
        .payload_size = 1200,
    };

    bool want_stats = false;

    static struct option long_opts[] = {
        {"dev", required_argument, 0, 0},
        {"mode", required_argument, 0, 0},
        {"bind", required_argument, 0, 0},
        {"dst", required_argument, 0, 0},
        {"port", required_argument, 0, 0},
        {"rate", required_argument, 0, 0},
        {"payload", required_argument, 0, 0},
        {"stats", no_argument, 0, 0},
        {0,0,0,0}
    };

    for (;;) {
        int idx = 0;
        int c = getopt_long(argc, argv, "", long_opts, &idx);
        if (c == -1) break;
        if (c != 0) continue;

        const char *opt = long_opts[idx].name;
        if (!strcmp(opt, "dev")) cfg.dev = optarg;
        else if (!strcmp(opt, "mode")) cfg.mode = optarg;
        else if (!strcmp(opt, "bind")) cfg.bind_ip = optarg;
        else if (!strcmp(opt, "dst")) cfg.dst_ip = optarg;
        else if (!strcmp(opt, "port")) cfg.port = atoi(optarg);
        else if (!strcmp(opt, "rate")) cfg.rate_pps = atoi(optarg);
        else if (!strcmp(opt, "payload")) cfg.payload_size = atoi(optarg);
        else if (!strcmp(opt, "stats")) want_stats = true;
    }

    if (!cfg.mode) {
        usage(argv[0]);
        return 2;
    }

    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    int devfd = open_dev(cfg.dev);
    if (devfd < 0) return 1;

    struct rtpm_config kcfg;
    if (get_cfg(devfd, &kcfg) != 0) {
        close(devfd);
        return 1;
    }

    struct shared_layout sh;
    if (map_shared(devfd, &kcfg, &sh) != 0) {
        close(devfd);
        return 1;
    }

    if (!strcmp(cfg.mode, "ctl")) {
        if (want_stats) print_stats(devfd);
        munmap(sh.base, sh.len);
        close(devfd);
        return 0;
    }

    if (start_mod(devfd) != 0) {
        munmap(sh.base, sh.len);
        close(devfd);
        return 1;
    }

    pthread_t t;
    int sock = -1;

    if (!strcmp(cfg.mode, "rx")) {
        sock = udp_socket_bind(cfg.bind_ip, cfg.port);
        if (sock < 0) {
            fprintf(stderr, "bind socket failed: %s\n", strerror(errno));
            stop_mod(devfd);
            munmap(sh.base, sh.len);
            close(devfd);
            return 1;
        }
        struct rx_ctx ctx = { .devfd = devfd, .sock = sock, .sh = sh };
        pthread_create(&t, NULL, rx_thread, &ctx);
        while (!g_stop) {
            usleep(500000);
            print_stats(devfd);
        }
        pthread_join(t, NULL);
    } else if (!strcmp(cfg.mode, "tx")) {
        if (!cfg.dst_ip) {
            fprintf(stderr, "--dst is required in tx mode\n");
            stop_mod(devfd);
            munmap(sh.base, sh.len);
            close(devfd);
            return 2;
        }
        sock = udp_socket_connect(cfg.dst_ip, cfg.port);
        if (sock < 0) {
            fprintf(stderr, "connect socket failed: %s\n", strerror(errno));
            stop_mod(devfd);
            munmap(sh.base, sh.len);
            close(devfd);
            return 1;
        }

        /* Pre-fill ring with payloads so POP_SLOT has data to send */
        for (uint32_t i = 0; i < sh.ring_size; i++) {
            struct rtpm_slot_desc *sd = slot_desc(&sh, i);
            uint8_t *pl = slot_payload_ptr(&sh, i);

            uint32_t plen = (uint32_t)cfg.payload_size;
            if (plen > sh.slot_payload) plen = sh.slot_payload;

            /* demo payload pattern */
            for (uint32_t j = 0; j < plen; j++) pl[j] = (uint8_t)(j & 0xFF);

            sd->index = i;
            sd->payload_len = plen;
            sd->rtp_seq = 0;
            sd->rtp_ts = 0;

            if (ioctl(devfd, RTPM_IOCTL_PUSH_SLOT, sd) != 0) {
                /* ring might not accept all at once; stop early */
                break;
            }
        }

        struct tx_ctx ctx = { .devfd = devfd, .sock = sock, .sh = sh, .rate_pps = cfg.rate_pps, .ssrc = 0x12345678 };
        pthread_create(&t, NULL, tx_thread, &ctx);

        while (!g_stop) {
            usleep(500000);
            print_stats(devfd);
        }
        pthread_join(t, NULL);
    } else {
        usage(argv[0]);
    }

    if (sock >= 0) close(sock);
    stop_mod(devfd);
    munmap(sh.base, sh.len);
    close(devfd);
    return 0;
}
