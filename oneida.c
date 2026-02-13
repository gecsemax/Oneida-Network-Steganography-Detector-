#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define MAX_FLOWS           16384
#define FLOW_HASH_SIZE      4096
#define WINDOW_SIZE         256
#define NUM_CHANNELS        12
#define COMPOSITE_THRESH    0.45

typedef enum { MODE_LIVE, MODE_PCAP, MODE_PCAPNG } ingest_mode_t;

/* ML‑style feature vector (12 channels, extended) */
typedef struct {
    double ipd_mean, ipd_std;
    double len_mean, len_std;
    double proto_entropy, flag_entropy;
    double seq_var, ack_var, window_var;
    double ttl_var, ipid_pred, payload_entropy;
} ml_features_t;

typedef struct flow_t flow_t;

/* Per‑flow state */
struct flow_t {
    uint64_t flow_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  l3_proto, l4_proto;

    /* Sliding window */
    double   times[WINDOW_SIZE];
    uint16_t lengths[WINDOW_SIZE];
    uint8_t  protocols[WINDOW_SIZE];
    uint8_t  flags[WINDOW_SIZE];
    uint8_t  ttls[WINDOW_SIZE];
    uint32_t seqs[WINDOW_SIZE];
    uint32_t acks[WINDOW_SIZE];
    uint16_t win_sizes[WINDOW_SIZE];

    int      pkt_count;

    /* Scores */
    double        channel_scores[NUM_CHANNELS];
    double        composite_score;
    ml_features_t ml_features;

    /* Metadata */
    double          first_seen, last_seen;
    pthread_mutex_t lock;

    /* Hash chain */
    flow_t *next;
};

static flow_t *g_flow_table[FLOW_HASH_SIZE];
static volatile int g_running = 1;
static pthread_mutex_t g_table_lock = PTHREAD_MUTEX_INITIALIZER;
static int g_flow_count = 0;

/* Simple 64‑bit mix */
static inline uint64_t mix64(uint64_t x) {
    x ^= x >> 33;
    x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33;
    x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static inline uint32_t flow_hash(uint64_t flow_id) {
    return (uint32_t)(mix64(flow_id) & (FLOW_HASH_SIZE - 1));
}

/* === IPv4/TCP/UDP parser === */
static inline int parse_packet(const u_char *pkt, int caplen,
                               uint64_t *flow_id, uint16_t *pkt_len,
                               uint8_t *l4_proto, uint16_t *src_port,
                               uint16_t *dst_port, uint8_t *ttl,
                               uint8_t *flags, uint32_t *seq,
                               uint32_t *ack, uint16_t *win)
{
    if (caplen < 34) return -1; /* Ethernet + IPv4 min */

    const int l2_len = 14;      /* DLT_EN10MB */
    const u_char *ip_ptr = pkt + l2_len;
    struct ip *iph = (struct ip *)ip_ptr;
    if (iph->ip_v != 4) return -1;

    int ip_hlen = iph->ip_hl * 4;
    if (caplen < l2_len + ip_hlen) return -1;

    *l4_proto = iph->ip_p;
    *pkt_len  = ntohs(iph->ip_len);
    *ttl      = iph->ip_ttl;

    uint32_t src = iph->ip_src.s_addr;
    uint32_t dst = iph->ip_dst.s_addr;

    const u_char *l4 = ip_ptr + ip_hlen;

    *flags = 0;
    *seq   = 0;
    *ack   = 0;
    *win   = 0;

    if (*l4_proto == IPPROTO_TCP) {
        if (caplen < l2_len + ip_hlen + (int)sizeof(struct tcphdr)) return -1;
        struct tcphdr *tcph = (struct tcphdr *)l4;
        *src_port = ntohs(tcph->th_sport);
        *dst_port = ntohs(tcph->th_dport);
        *flags    = tcph->th_flags;
        *seq      = ntohl(tcph->th_seq);
        *ack      = ntohl(tcph->th_ack);
        *win      = ntohs(tcph->th_win);
    } else if (*l4_proto == IPPROTO_UDP) {
        if (caplen < l2_len + ip_hlen + (int)sizeof(struct udphdr)) return -1;
        struct udphdr *udph = (struct udphdr *)l4;
        *src_port = ntohs(udph->uh_sport);
        *dst_port = ntohs(udph->uh_dport);
    } else {
        return -1;
    }

    *flow_id = (uint64_t)src ^
               ((uint64_t)dst << 32) ^
               ((uint64_t)(*src_port) << 16) ^
               ((uint64_t)(*dst_port)) ^
               ((uint64_t)(*l4_proto) << 48);

    return 0;
}

/* === Flow lookup/creation using hash table === */
static flow_t *get_flow(uint64_t flow_id,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t l4_proto, double now)
{
    uint32_t h = flow_hash(flow_id);

    pthread_mutex_lock(&g_table_lock);
    flow_t *f = g_flow_table[h];

    while (f) {
        if (f->flow_id == flow_id) {
            pthread_mutex_lock(&f->lock);
            pthread_mutex_unlock(&g_table_lock);
            return f;
        }
        f = f->next;
    }

    if (g_flow_count >= MAX_FLOWS) {
        pthread_mutex_unlock(&g_table_lock);
        return NULL;
    }

    f = calloc(1, sizeof(flow_t));
    if (!f) {
        pthread_mutex_unlock(&g_table_lock);
        return NULL;
    }

    f->flow_id    = flow_id;
    f->src_ip     = src_ip;
    f->dst_ip     = dst_ip;
    f->src_port   = src_port;
    f->dst_port   = dst_port;
    f->l3_proto   = 4;
    f->l4_proto   = l4_proto;
    f->first_seen = f->last_seen = now;
    pthread_mutex_init(&f->lock, NULL);

    f->next = g_flow_table[h];
    g_flow_table[h] = f;
    g_flow_count++;

    pthread_mutex_lock(&f->lock);
    pthread_mutex_unlock(&g_table_lock);
    return f;
}

/* === Simple entropy helper === */
static double entropy_from_hist(const int *hist, int size, int n) {
    if (n <= 0) return 0.0;
    double H = 0.0;
    for (int i = 0; i < size; i++) {
        if (!hist[i]) continue;
        double p = (double)hist[i] / n;
        H -= p * log2(p);
    }
    return H;
}

/* === 12‑channel scoring === */
static void compute_scores(flow_t *flow)
{
    if (flow->pkt_count < 20)
        return;

    int n = (flow->pkt_count < WINDOW_SIZE) ? flow->pkt_count : WINDOW_SIZE;

    /* Channel 0: timing IPD statistics */
    int valid_ipd = 0;
    double ipd_mean = 0.0, ipd_var = 0.0;

    for (int i = 1; i < n; i++) {
        double ipd = flow->times[i] - flow->times[i - 1];
        if (ipd > 0) {
            ipd_mean += ipd;
            valid_ipd++;
        }
    }

    if (valid_ipd > 10) {
        ipd_mean /= valid_ipd;
        for (int i = 1; i < n; i++) {
            double ipd = flow->times[i] - flow->times[i - 1];
            if (ipd > 0) {
                double d = ipd - ipd_mean;
                ipd_var += d * d;
            }
        }
        flow->ml_features.ipd_mean = ipd_mean;
        flow->ml_features.ipd_std  = sqrt(ipd_var / valid_ipd);
        flow->channel_scores[0]    = (flow->ml_features.ipd_std < 0.01) ? 0.8 : 0.1;
    }

    /* Channel 1: packet length variability */
    double len_mean = 0.0, len_var = 0.0;
    for (int i = 0; i < n; i++)
        len_mean += flow->lengths[i];

    if (n > 0) {
        len_mean /= n;
        for (int i = 0; i < n; i++) {
            double d = flow->lengths[i] - len_mean;
            len_var += d * d;
        }
        flow->ml_features.len_mean = len_mean;
        flow->ml_features.len_std  = sqrt(len_var / n);
        flow->channel_scores[1]    = (flow->ml_features.len_std < 10.0) ? 0.6 : 0.1;
    }

    /* Channel 2: protocol entropy (TCP vs UDP etc.) */
    int proto_hist[256] = {0};
    for (int i = 0; i < n; i++)
        proto_hist[flow->protocols[i]]++;

    double proto_H = entropy_from_hist(proto_hist, 256, n);
    flow->ml_features.proto_entropy = proto_H;
    flow->channel_scores[2]         = (proto_H > 0.1) ? 0.3 : 0.0;

    /* Channel 3: TCP flag entropy (only meaningful for TCP flows) */
    int flag_hist[256] = {0};
    int flag_n = 0;
    for (int i = 0; i < n; i++) {
        if (flow->flags[i]) {
            flag_hist[flow->flags[i]]++;
            flag_n++;
        }
    }
    double flag_H = entropy_from_hist(flag_hist, 256, flag_n);
    flow->ml_features.flag_entropy = flag_H;
    flow->channel_scores[3]        = (flag_H < 0.5 && flag_n > 0) ? 0.5 : 0.1;

    /* Channels 4–6: seq/ack/window variance (TCP only) */
    if (flow->l4_proto == IPPROTO_TCP) {
        double seq_mean = 0.0, ack_mean = 0.0, win_mean = 0.0;
        int seq_n = 0, ack_n = 0, win_n = 0;

        for (int i = 0; i < n; i++) {
            if (flow->seqs[i]) { seq_mean += flow->seqs[i]; seq_n++; }
            if (flow->acks[i]) { ack_mean += flow->acks[i]; ack_n++; }
            if (flow->win_sizes[i]) { win_mean += flow->win_sizes[i]; win_n++; }
        }

        double seq_var = 0.0, ack_var = 0.0, win_var = 0.0;

        if (seq_n > 0) {
            seq_mean /= seq_n;
            for (int i = 0; i < n; i++) {
                if (flow->seqs[i]) {
                    double d = flow->seqs[i] - seq_mean;
                    seq_var += d * d;
                }
            }
            seq_var /= seq_n;
        }

        if (ack_n > 0) {
            ack_mean /= ack_n;
            for (int i = 0; i < n; i++) {
                if (flow->acks[i]) {
                    double d = flow->acks[i] - ack_mean;
                    ack_var += d * d;
                }
            }
            ack_var /= ack_n;
        }

        if (win_n > 0) {
            win_mean /= win_n;
            for (int i = 0; i < n; i++) {
                if (flow->win_sizes[i]) {
                    double d = flow->win_sizes[i] - win_mean;
                    win_var += d * d;
                }
            }
            win_var /= win_n;
        }

        flow->ml_features.seq_var    = seq_var;
        flow->ml_features.ack_var    = ack_var;
        flow->ml_features.window_var = win_var;

        flow->channel_scores[4] = (seq_var < 1e6 && seq_n > 10) ? 0.4 : 0.1;
        flow->channel_scores[5] = (ack_var < 1e6 && ack_n > 10) ? 0.4 : 0.1;
        flow->channel_scores[6] = (win_var < 1e4 && win_n > 10) ? 0.4 : 0.1;
    }

    /* Channel 7: TTL variance */
    double ttl_mean = 0.0, ttl_var = 0.0;
    for (int i = 0; i < n; i++)
        ttl_mean += flow->ttls[i];
    ttl_mean /= n;
    for (int i = 0; i < n; i++) {
        double d = flow->ttls[i] - ttl_mean;
        ttl_var += d * d;
    }
    ttl_var /= n;
    flow->ml_features.ttl_var = ttl_var;
    flow->channel_scores[7]   = (ttl_var < 5.0) ? 0.4 : 0.1;

    /* Channel 8: IPID predictability (placeholder) */
    /* Not tracked in this version; keep 0.0 or small baseline */
    flow->ml_features.ipid_pred = 0.0;
    flow->channel_scores[8]     = 0.0;

    /* Channel 9: payload entropy (placeholder, header‑only) */
    /* Without payload capture, we approximate as 0.0 */
    flow->ml_features.payload_entropy = 0.0;
    flow->channel_scores[9]           = 0.0;

    /* Channels 10–11: reserved for future ML features */
    flow->channel_scores[10] = 0.0;
    flow->channel_scores[11] = 0.0;

    /* Composite score: average over all 12 channels */
    flow->composite_score = 0.0;
    for (int i = 0; i < NUM_CHANNELS; i++)
        flow->composite_score += flow->channel_scores[i];
    flow->composite_score /= NUM_CHANNELS;
}

/* === Packet processor === */
void process_packet(u_char *user, const struct pcap_pkthdr *hdr,
                    const u_char *pkt)
{
    (void)user;

    uint64_t flow_id;
    uint16_t pkt_len, src_port = 0, dst_port = 0;
    uint8_t  l4_proto, ttl, flags;
    uint32_t seq, ack;
    uint16_t win;

    double timestamp = (double)hdr->ts.tv_sec +
                       (double)hdr->ts.tv_usec / 1e6;

    if (parse_packet(pkt, hdr->caplen, &flow_id, &pkt_len,
                     &l4_proto, &src_port, &dst_port,
                     &ttl, &flags, &seq, &ack, &win) < 0)
        return;

    const int l2_len = 14;
    struct ip *iph = (struct ip *)(pkt + l2_len);
    uint32_t src_ip = iph->ip_src.s_addr;
    uint32_t dst_ip = iph->ip_dst.s_addr;

    flow_t *flow = get_flow(flow_id, src_ip, dst_ip,
                            src_port, dst_port, l4_proto, timestamp);
    if (!flow)
        return;

    int idx = flow->pkt_count % WINDOW_SIZE;
    flow->times[idx]     = timestamp;
    flow->lengths[idx]   = pkt_len;
    flow->protocols[idx] = l4_proto;
    flow->flags[idx]     = flags;
    flow->ttls[idx]      = ttl;
    flow->seqs[idx]      = seq;
    flow->acks[idx]      = ack;
    flow->win_sizes[idx] = win;

    flow->pkt_count++;
    flow->last_seen = timestamp;

    compute_scores(flow);

    if (flow->composite_score > COMPOSITE_THRESH && flow->pkt_count > 30) {
        printf("\n🚨 STEG ALERT [%.2f] %016llx | %hu→%hu | Pkts:%d | L4:%s\n",
               flow->composite_score,
               (unsigned long long)flow_id,
               src_port, dst_port, flow->pkt_count,
               (l4_proto == IPPROTO_TCP) ? "TCP" : "UDP");
        printf("   Timing:%.2f Len:%.2f Proto:%.2f Flags:%.2f TTL:%.2f\n",
               flow->channel_scores[0],
               flow->channel_scores[1],
               flow->channel_scores[2],
               flow->channel_scores[3],
               flow->channel_scores[7]);
    }

    pthread_mutex_unlock(&flow->lock);
}

/* === Cleanup thread: expire idle flows === */
void *cleanup_thread(void *arg)
{
    (void)arg;

    while (g_running) {
        double now = (double)time(NULL);

        pthread_mutex_lock(&g_table_lock);
        for (int i = 0; i < FLOW_HASH_SIZE; i++) {
            flow_t *prev = NULL;
            flow_t *f = g_flow_table[i];

            while (f) {
                pthread_mutex_lock(&f->lock);
                if ((now - f->last_seen) > 300.0) { /* 5 minutes idle */
                    flow_t *to_free = f;
                    if (prev)
                        prev->next = f->next;
                    else
                        g_flow_table[i] = f->next;

                    f = f->next;
                    pthread_mutex_unlock(&to_free->lock);
                    pthread_mutex_destroy(&to_free->lock);
                    free(to_free);
                    g_flow_count--;
                    continue;
                }
                pthread_mutex_unlock(&f->lock);
                prev = f;
                f = f->next;
            }
        }
        pthread_mutex_unlock(&g_table_lock);

        sleep(30);
    }

    return NULL;
}

/* === main() === */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <interface|pcap_file>\n", argv[0]);
        printf("Example: %s lo0\n", argv[0]);
        return 1;
    }

    printf("=== Oneida v3.1 Enterprise (Hash + UDP) ===\n");
    printf("12‑Channel Steganography Detection | macOS‑compatible core\n\n");

    pthread_t cleanup_tid;
    pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = (strstr(argv[1], ".pcap") != NULL)
                         ? pcap_open_offline(argv[1], errbuf)
                         : pcap_open_live(argv[1], 9216, 1, 1, errbuf);

    if (!handle) {
        fprintf(stderr, "Error: %s\n", errbuf);
        g_running = 0;
        pthread_join(cleanup_tid, NULL);
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp or udp", 0, PCAP_NETMASK_UNKNOWN) == 0)
        pcap_setfilter(handle, &fp);

    printf("✅ Capturing on %s | Ctrl+C to stop\n", argv[1]);
    printf("Threshold: %.2f | Max flows: %d | Window: %d | Hash buckets: %d\n\n",
           COMPOSITE_THRESH, MAX_FLOWS, WINDOW_SIZE, FLOW_HASH_SIZE);

    pcap_loop(handle, 0, process_packet, NULL);

    g_running = 0;
    pthread_join(cleanup_tid, NULL);
    pcap_close(handle);
    return 0;
}
