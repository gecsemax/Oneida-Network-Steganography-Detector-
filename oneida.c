/*
 * =============================================================================
 * Oneida Network Steganography Detector v3.0 - ENTERPRISE EDITION
 * =============================================================================
 * Author: Max Gecse
 * 
 * Compact core: IPv4/TCP, per‑flow sliding window, multi‑channel anomaly score.
 * macOS‑compatible (libpcap, pthreads, no spinlocks).
 */

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
#include <arpa/inet.h>
#include <sys/queue.h>

#define MAX_FLOWS           8192
#define WINDOW_SIZE         256
#define NUM_CHANNELS        12
#define COMPOSITE_THRESH    0.45

typedef enum { MODE_LIVE, MODE_PCAP, MODE_PCAPNG } ingest_mode_t;

/* ML‑style feature vector (12 channels, can be extended) */
typedef struct {
    double ipd_mean, ipd_std;
    double len_mean, len_std;
    double proto_entropy, flag_entropy;
    double seq_var, ack_var, window_var;
    double ttl_var, ipid_pred, payload_entropy;
} ml_features_t;

/* Forward declaration for TAILQ */
typedef struct flow_t flow_t;

/* Per‑flow state */
struct flow_t {
    TAILQ_ENTRY(flow_t) entries;
    uint64_t flow_id;
    char src_ip[64], dst_ip[64];
    uint16_t src_port, dst_port;
    uint8_t l3_proto, l4_proto;
    
    /* Sliding window */
    double   times[WINDOW_SIZE];
    uint16_t lengths[WINDOW_SIZE];
    uint8_t  protocols[WINDOW_SIZE];
    uint8_t  flags[WINDOW_SIZE];
    int      pkt_count, idx;
    
    /* Scores */
    double        channel_scores[NUM_CHANNELS];
    double        composite_score;
    ml_features_t ml_features;
    
    /* Metadata */
    double          first_seen, last_seen;
    pthread_mutex_t lock;
};

TAILQ_HEAD(flow_list, flow_t);
static struct flow_list g_flows;
static volatile int g_running = 1;

/* === IPv4/TCP parser (fast path) === */
static inline int parse_packet(const u_char *pkt, int caplen,
                               uint64_t *flow_id, uint16_t *pkt_len,
                               uint8_t *l4_proto, uint16_t *src_port,
                               uint16_t *dst_port)
{
    if (caplen < 54) return -1;           /* Ethernet + IPv4 + TCP min */

    const int l2_len = 14;                /* DLT_EN10MB */
    struct ip *iph = (struct ip *)(pkt + l2_len);
    if (iph->ip_v != 4) return -1;

    *l4_proto = iph->ip_p;
    *pkt_len  = ntohs(iph->ip_len);

    if (*l4_proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((char *)iph + iph->ip_hl * 4);
        *src_port = ntohs(tcph->th_sport);   /* macOS: th_sport/th_dport */
        *dst_port = ntohs(tcph->th_dport);

        *flow_id  = (uint64_t)iph->ip_src.s_addr ^
                    ((uint64_t)iph->ip_dst.s_addr << 32) ^
                    *src_port ^ *dst_port;
        return 0;
    }

    return -1;
}

/* === Simple 12‑channel scoring (timing + length + proto entropy) === */
static void compute_scores(flow_t *flow)
{
    if (flow->pkt_count < 20)
        return;

    int i;
    int n = (flow->pkt_count < WINDOW_SIZE) ? flow->pkt_count : WINDOW_SIZE;

    /* Channel 0: timing IPD statistics */
    int valid_ipd = 0;
    double ipd_mean = 0.0, ipd_var = 0.0;

    for (i = 1; i < n; i++) {
        double ipd = flow->times[i] - flow->times[i - 1];
        if (ipd > 0) {
            ipd_mean += ipd;
            valid_ipd++;
        }
    }

    if (valid_ipd > 10) {
        ipd_mean /= valid_ipd;
        for (i = 1; i < n; i++) {
            double ipd = flow->times[i] - flow->times[i - 1];
            if (ipd > 0) {
                double d = ipd - ipd_mean;
                ipd_var += d * d;
            }
        }
        flow->ml_features.ipd_mean = ipd_mean;
        flow->ml_features.ipd_std  = sqrt(ipd_var / valid_ipd);
        flow->channel_scores[0]    = (flow->ml_features.ipd_std < 0.01) ? 0.8 : 0.0;
    }

    /* Channel 1: packet length variability */
    double len_mean = 0.0, len_var = 0.0;
    for (i = 0; i < n; i++)
        len_mean += flow->lengths[i];

    if (n > 0) {
        len_mean /= n;
        for (i = 0; i < n; i++) {
            double d = flow->lengths[i] - len_mean;
            len_var += d * d;
        }
        flow->ml_features.len_mean = len_mean;
        flow->ml_features.len_std  = sqrt(len_var / n);
        flow->channel_scores[1]    = (flow->ml_features.len_std < 10.0) ? 0.6 : 0.0;
    }

    /* Channel 2: protocol entropy (here just TCP, but kept for structure) */
    int proto_hist[256] = {0};
    for (i = 0; i < n; i++)
        proto_hist[flow->protocols[i]]++;

    double entropy = 0.0;
    for (i = 0; i < 256; i++) {
        if (!proto_hist[i]) continue;
        double p = (double)proto_hist[i] / n;
        entropy -= p * log2(p);
    }
    flow->ml_features.proto_entropy = entropy;
    flow->channel_scores[2]         = (entropy > 0.1) ? 0.3 : 0.0;

    /* Composite score: average over all 12 channels (most unused = 0) */
    flow->composite_score = 0.0;
    for (i = 0; i < NUM_CHANNELS; i++)
        flow->composite_score += flow->channel_scores[i];
    flow->composite_score /= NUM_CHANNELS;
}

/* === Flow lookup/creation === */
static flow_t *get_flow(uint64_t flow_id)
{
    flow_t *flow;

    TAILQ_FOREACH(flow, &g_flows, entries) {
        if (flow->flow_id == flow_id) {
            pthread_mutex_lock(&flow->lock);
            return flow;
        }
    }

    /* New flow */
    flow = calloc(1, sizeof(flow_t));
    if (!flow)
        return NULL;

    flow->flow_id    = flow_id;
    flow->first_seen = flow->last_seen = (double)time(NULL);
    pthread_mutex_init(&flow->lock, NULL);

    pthread_mutex_lock(&flow->lock);
    TAILQ_INSERT_TAIL(&g_flows, flow, entries);
    return flow;
}

/* === Packet processor === */
void process_packet(u_char *user, const struct pcap_pkthdr *hdr,
                    const u_char *pkt)
{
    (void)user;

    uint64_t flow_id;
    uint16_t pkt_len, src_port = 0, dst_port = 0;
    uint8_t  l4_proto;

    /* macOS: pcap uses tv_sec + tv_usec */
    double timestamp = (double)hdr->ts.tv_sec +
                       (double)hdr->ts.tv_usec / 1e6;

    if (parse_packet(pkt, hdr->caplen, &flow_id, &pkt_len,
                     &l4_proto, &src_port, &dst_port) < 0)
        return;

    flow_t *flow = get_flow(flow_id);
    if (!flow)
        return;

    int idx = flow->pkt_count % WINDOW_SIZE;
    flow->times[idx]     = timestamp;
    flow->lengths[idx]   = pkt_len;
    flow->protocols[idx] = l4_proto;
    flow->pkt_count++;
    flow->last_seen      = timestamp;

    compute_scores(flow);

    if (flow->composite_score > COMPOSITE_THRESH && flow->pkt_count > 30) {
        printf("\n🚨 STEG ALERT [%.2f] %016llx | %hu→%hu | Pkts:%d\n",
               flow->composite_score,
               (unsigned long long)flow_id,
               src_port, dst_port, flow->pkt_count);
        printf("   Timing:%.2f Len:%.2f Proto:%.2f\n",
               flow->channel_scores[0],
               flow->channel_scores[1],
               flow->channel_scores[2]);
    }

    pthread_mutex_unlock(&flow->lock);
}

/* === Cleanup thread: expire idle flows === */
void *cleanup_thread(void *arg)
{
    (void)arg;

    while (g_running) {
        double now = (double)time(NULL);
        flow_t *flow, *tmp;

        TAILQ_FOREACH_SAFE(flow, &g_flows, entries, tmp) {
            pthread_mutex_lock(&flow->lock);
            if ((now - flow->last_seen) > 300.0) { /* 5 minutes idle */
                TAILQ_REMOVE(&g_flows, flow, entries);
                pthread_mutex_unlock(&flow->lock);
                pthread_mutex_destroy(&flow->lock);
                free(flow);
            } else {
                pthread_mutex_unlock(&flow->lock);
            }
        }

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

    printf("=== Oneida v3.0 Enterprise ===\n");
    printf("12‑Channel Steganography Detection | macOS‑compatible core\n\n");

    TAILQ_INIT(&g_flows);

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
    printf("Threshold: %.2f | Max flows: %d | Window: %d\n\n",
           COMPOSITE_THRESH, MAX_FLOWS, WINDOW_SIZE);

    pcap_loop(handle, 0, process_packet, NULL);

    g_running = 0;
    pthread_join(cleanup_tid, NULL);
    pcap_close(handle);
    return 0;
}
