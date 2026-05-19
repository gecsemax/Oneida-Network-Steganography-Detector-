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
#include <stdatomic.h>
#include <semaphore.h>
#include <unistd.h>
#include <getopt.h>
#include <sched.h>
#include <sys/stat.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

/* basic limits and defaults */

#ifndef MAX_FLOWS
#  define MAX_FLOWS              32768
#endif

#ifndef FLOW_TABLE_SIZE
#  define FLOW_TABLE_SIZE        8192
#endif

#ifndef FLOW_WINDOW_SIZE
#  define FLOW_WINDOW_SIZE       256
#endif

#define FEATURE_CHANNELS         12
#define RING_BUFFER_SIZE         65536
#define RING_BUFFER_MASK         (RING_BUFFER_SIZE - 1)

#define DEFAULT_SCORE_THRESHOLD  0.45
#define DEFAULT_IDLE_TIMEOUT     300
#define DEFAULT_MAX_LIFETIME     3600
#define DEFAULT_ALERT_COOLDOWN   5.0

#define CAPTURE_SNAPLEN          9216
#define MIN_PACKETS_FOR_SCORE    20
#define MIN_PACKETS_FOR_ALERT    30

#define L2_ETHERNET_LEN          14

#define SEQ_CACHE_BITS           9
#define SEQ_CACHE_SIZE           (1u << SEQ_CACHE_BITS)
#define SEQ_CACHE_MASK           (SEQ_CACHE_SIZE - 1)

#define KERNEL_RING_BYTES        (64 * 1024 * 1024)
#define RESCORE_STEP             (FLOW_WINDOW_SIZE / 4)

#define DNS_RATE_WINDOW_SEC      10.0
#define DNS_RATE_THRESHOLD       10

/* small sequence cache for retransmission detection */

typedef struct {
    uint32_t keys[SEQ_CACHE_SIZE];
    uint8_t  used[SEQ_CACHE_SIZE];
} seq_cache_t;

static inline int seq_cache_has(const seq_cache_t *c, uint32_t seq)
{
    uint32_t slot = seq & SEQ_CACHE_MASK;
    return c->used[slot] && c->keys[slot] == seq;
}

static inline void seq_cache_add(seq_cache_t *c, uint32_t seq)
{
    uint32_t slot = seq & SEQ_CACHE_MASK;
    c->keys[slot] = seq;
    c->used[slot] = 1;
}

static inline void seq_cache_reset(seq_cache_t *c)
{
    memset(c->used, 0, sizeof(c->used));
}

/* DNS tunnel heuristics */

typedef struct {
    uint32_t query_count;
    uint32_t txt_or_null_count;
    uint32_t encoded_label_count;
    uint32_t long_label_count;
    double   window_start;
    uint32_t window_queries;
    double   score;
} dns_state_t;

static int label_looks_encoded(const char *s)
{
    int len = (int)strlen(s);
    if (len < 16) {
        return 0;
    }

    int base32_like = 0;
    int base64_like = 0;

    for (int i = 0; i < len; i++) {
        char c = s[i];

        if ((c >= 'A' && c <= 'Z') ||
            (c >= '2' && c <= '7') ||
            c == '=') {
            base32_like++;
        }

        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '+' || c == '/' || c == '=') {
            base64_like++;
        }
    }

    int pct32 = (base32_like * 100) / len;
    int pct64 = (base64_like * 100) / len;

    return (pct32 > 80) || (pct64 > 85);
}

static double dns_tunnel_score(dns_state_t *st,
                               double now,
                               const char *qname,
                               uint8_t qtype)
{
    st->query_count++;

    if (now - st->window_start > DNS_RATE_WINDOW_SEC) {
        st->window_start   = now;
        st->window_queries = 0;
    }

    st->window_queries++;

    if (qtype == 16 || qtype == 10) {
        st->txt_or_null_count++;
    }

    char tmp[256];
    strncpy(tmp, qname, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    char *token = tmp;
    char *p     = tmp;

    while (*p) {
        if (*p == '.') {
            *p = '\0';
            int len = (int)strlen(token);
            if (len > 40) {
                st->long_label_count++;
            }
            if (label_looks_encoded(token)) {
                st->encoded_label_count++;
            }
            token = p + 1;
        }
        p++;
    }

    int len = (int)strlen(token);
    if (len > 40) {
        st->long_label_count++;
    }
    if (label_looks_encoded(token)) {
        st->encoded_label_count++;
    }

    double s = 0.0;

    if (st->window_queries > DNS_RATE_THRESHOLD) {
        s += 0.40;
    }
    if (st->txt_or_null_count > 2) {
        s += 0.30;
    }
    if (st->encoded_label_count > 2) {
        s += 0.35;
    }
    if (st->long_label_count > 1) {
        s += 0.25;
    }

    if (s > 0.90) {
        s = 0.90;
    }

    st->score = s;
    return s;
}

/* runtime configuration */

typedef struct {
    const char *iface_or_file;
    double      score_threshold;
    double      alert_cooldown;
    int         idle_timeout;
    int         max_lifetime;
    int         json_output;
    int         promiscuous;
    int         worker_core;
    int         cleanup_core;
    int         verbose;
    int         use_nano_ts;
} runtime_cfg_t;

static runtime_cfg_t g_cfg = {
    .iface_or_file   = NULL,
    .score_threshold = DEFAULT_SCORE_THRESHOLD,
    .alert_cooldown  = DEFAULT_ALERT_COOLDOWN,
    .idle_timeout    = DEFAULT_IDLE_TIMEOUT,
    .max_lifetime    = DEFAULT_MAX_LIFETIME,
    .json_output     = 0,
    .promiscuous     = 1,
    .worker_core     = -1,
    .cleanup_core    = -1,
    .verbose         = 0,
    .use_nano_ts     = 0
};

/* feature vector per flow */

typedef struct {
    double ipd_mean;
    double ipd_std;
    double ipd_cvar;

    double len_mean;
    double len_std;

    double proto_entropy;
    double flag_entropy;

    double seq_var;
    double ack_var;
    double win_var;

    double ttl_var;
    double ipid_score;
    double payload_entropy;

    double burst_score;
    double asymmetry_ratio;

    int    retrans_count;
} feature_vec_t;

/* forward declaration */

typedef struct flow_entry flow_entry_t;

/* flow record */

struct flow_entry {
    uint64_t flow_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  l4_proto;

    double   times[FLOW_WINDOW_SIZE];
    uint16_t lengths[FLOW_WINDOW_SIZE];
    uint8_t  protocols[FLOW_WINDOW_SIZE];
    uint8_t  flags[FLOW_WINDOW_SIZE];
    uint8_t  ttls[FLOW_WINDOW_SIZE];
    uint32_t seqs[FLOW_WINDOW_SIZE];
    uint32_t acks[FLOW_WINDOW_SIZE];
    uint16_t win_sizes[FLOW_WINDOW_SIZE];
    uint16_t ip_ids[FLOW_WINDOW_SIZE];
    uint8_t  slot_valid[FLOW_WINDOW_SIZE];

    seq_cache_t seq_cache;
    dns_state_t dns_state;

    uint64_t bytes_fwd;
    uint64_t bytes_rev;
    uint64_t pkt_count;
    uint32_t retrans_count;
    uint32_t fragment_count;
    uint32_t icmp_count;

    double        channel_score[FEATURE_CHANNELS];
    double        composite_score;
    feature_vec_t features;

    double first_seen;
    double last_seen;
    double last_alert_time;
    int    needs_rescore;

    volatile int    being_removed;
    pthread_mutex_t lock;
    flow_entry_t   *next;
    int             pool_index;
};

/* simple slab pool for flows */

static flow_entry_t   g_flow_pool[MAX_FLOWS];
static uint8_t        g_flow_in_use[MAX_FLOWS];
static uint32_t       g_free_list[MAX_FLOWS];
static uint32_t       g_free_head = 0;
static uint32_t       g_free_tail = 0;
static pthread_mutex_t g_pool_mutex = PTHREAD_MUTEX_INITIALIZER;

static void flow_pool_init(void)
{
    for (int i = 0; i < MAX_FLOWS; i++) {
        g_free_list[i] = (uint32_t)i;
        g_flow_in_use[i] = 0;
    }
    g_free_head = 0;
    g_free_tail = (uint32_t)MAX_FLOWS;
}

static flow_entry_t *flow_pool_alloc(void)
{
    pthread_mutex_lock(&g_pool_mutex);

    if (g_free_head == g_free_tail) {
        pthread_mutex_unlock(&g_pool_mutex);
        return NULL;
    }

    int idx = (int)(g_free_list[g_free_head % MAX_FLOWS]);
    g_free_head++;
    g_flow_in_use[idx] = 1;

    pthread_mutex_unlock(&g_pool_mutex);

    memset(&g_flow_pool[idx], 0, sizeof(flow_entry_t));
    g_flow_pool[idx].pool_index = idx;
    return &g_flow_pool[idx];
}

static void flow_pool_free(flow_entry_t *f)
{
    int idx = f->pool_index;

    pthread_mutex_lock(&g_pool_mutex);
    g_flow_in_use[idx] = 0;
    g_free_list[g_free_tail % MAX_FLOWS] = (uint32_t)idx;
    g_free_tail++;
    pthread_mutex_unlock(&g_pool_mutex);
}

/* hash table for flows */

typedef struct {
    flow_entry_t    *head;
    pthread_rwlock_t lock;
} flow_bucket_t;

static flow_bucket_t g_flow_table[FLOW_TABLE_SIZE];
static atomic_int    g_flow_count = 0;
static volatile int  g_running    = 1;
static atomic_uint_least64_t g_alert_count = 0;

/* ring buffer for packets */

typedef struct {
    struct pcap_pkthdr hdr;
    u_char             data[CAPTURE_SNAPLEN];
} ring_packet_t;

typedef struct {
    ring_packet_t         slots[RING_BUFFER_SIZE];
    atomic_uint_least64_t head;
    atomic_uint_least64_t tail;
    atomic_uint_least64_t dropped;
} packet_ring_t;

static packet_ring_t g_ring;
static sem_t         g_ring_sem;

/* hashing helpers */

static inline uint64_t mix64(uint64_t x)
{
    x ^= x >> 33;
    x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33;
    x *= UINT64_C(0xc4ceb9fe1a85ec53);
    x ^= x >> 33;
    return x;
}

static inline uint32_t flow_bucket_index(uint64_t id)
{
    return (uint32_t)(mix64(id) & (FLOW_TABLE_SIZE - 1));
}

static inline uint64_t build_flow_id(uint32_t sip,
                                     uint32_t dip,
                                     uint16_t sp,
                                     uint16_t dp,
                                     uint8_t  proto)
{
    uint32_t lo_ip, hi_ip;
    uint16_t lo_pt, hi_pt;

    if (sip < dip || (sip == dip && sp <= dp)) {
        lo_ip = sip;
        hi_ip = dip;
        lo_pt = sp;
        hi_pt = dp;
    } else {
        lo_ip = dip;
        hi_ip = sip;
        lo_pt = dp;
        hi_pt = sp;
    }

    uint64_t id = (uint64_t)lo_ip | ((uint64_t)hi_ip << 32);
    id ^= ((uint64_t)lo_pt << 48) ^
          ((uint64_t)hi_pt << 56) ^
          ((uint64_t)proto << 40);

    return mix64(id);
}

/* DNS name decoding */

static int dns_read_name(const u_char *payload,
                         int plen,
                         int offset,
                         char *out,
                         int outlen)
{
    int pos     = offset;
    int written = 0;
    int jumps   = 0;

    while (pos < plen && jumps < 10) {
        uint8_t len = payload[pos];

        if (len == 0) {
            pos++;
            break;
        }

        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= plen) {
                break;
            }
            pos = ((len & 0x3F) << 8) | payload[pos + 1];
            jumps++;
            continue;
        }

        pos++;
        if (pos + len > plen) {
            break;
        }

        if (written > 0 && written < outlen - 1) {
            out[written++] = '.';
        }

        int copy_len = (len < outlen - written - 1)
                     ? len
                     : (outlen - written - 1);

        memcpy(out + written, payload + pos, copy_len);
        written += copy_len;
        pos     += len;
    }

    out[written] = '\0';
    return pos;
}

/* parsed packet representation */

typedef struct {
    uint64_t flow_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t pkt_len;
    uint16_t win;
    uint16_t ip_id;
    uint8_t  l4_proto;
    uint8_t  ttl;
    uint8_t  tcp_flags;
    uint32_t seq;
    uint32_t ack;
    int      payload_off;
    int      payload_len;
    int      is_fwd;
    int      is_fragment;
    char     dns_qname[256];
    uint8_t  dns_qtype;
    int      has_dns;
} parsed_packet_t;

/* packet parsing */

static int parse_packet(const u_char *pkt,
                        int caplen,
                        parsed_packet_t *out)
{
    if (caplen < L2_ETHERNET_LEN + 20) {
        return -1;
    }

    const u_char *ip = pkt + L2_ETHERNET_LEN;

    if (((ip[0] >> 4) & 0xF) != 4) {
        return -1;
    }

    uint8_t ihl = (ip[0] & 0xF) * 4;
    if (ihl < 20 || caplen < L2_ETHERNET_LEN + ihl) {
        return -1;
    }

    out->l4_proto = ip[9];
    out->pkt_len  = (uint16_t)((ip[2] << 8) | ip[3]);
    out->ttl      = ip[8];
    out->ip_id    = (uint16_t)((ip[4] << 8) | ip[5]);

    memcpy(&out->src_ip, ip + 12, 4);
    memcpy(&out->dst_ip, ip + 16, 4);
    out->src_ip = ntohl(out->src_ip);
    out->dst_ip = ntohl(out->dst_ip);

    uint16_t frag_field = (uint16_t)((ip[6] << 8) | ip[7]);
    out->is_fragment = ((frag_field & 0x1FFF) != 0) ||
                       ((frag_field >> 13) & 1);

    const u_char *l4 = ip + ihl;
    int l4_len = caplen - L2_ETHERNET_LEN - ihl;

    out->tcp_flags   = 0;
    out->seq         = 0;
    out->ack         = 0;
    out->win         = 0;
    out->src_port    = 0;
    out->dst_port    = 0;
    out->has_dns     = 0;
    out->payload_off = 0;
    out->payload_len = 0;

    if (out->l4_proto == IPPROTO_TCP) {
        if (l4_len < 20) {
            return -1;
        }

        uint8_t thl = ((l4[12] >> 4) & 0xF) * 4;
        if (thl < 20 || l4_len < thl) {
            return -1;
        }

        out->src_port  = (uint16_t)((l4[0] << 8) | l4[1]);
        out->dst_port  = (uint16_t)((l4[2] << 8) | l4[3]);
        out->seq       = (uint32_t)((l4[4] << 24) |
                                    (l4[5] << 16) |
                                    (l4[6] << 8)  |
                                    (l4[7]));
        out->ack       = (uint32_t)((l4[8] << 24) |
                                    (l4[9] << 16) |
                                    (l4[10] << 8) |
                                    (l4[11]));
        out->tcp_flags = l4[13];
        out->win       = (uint16_t)((l4[14] << 8) | l4[15]);

        out->payload_off = (int)(l4 - pkt) + thl;
        out->payload_len = l4_len - thl;

    } else if (out->l4_proto == IPPROTO_UDP) {
        if (l4_len < 8) {
            return -1;
        }

        out->src_port    = (uint16_t)((l4[0] << 8) | l4[1]);
        out->dst_port    = (uint16_t)((l4[2] << 8) | l4[3]);
        out->payload_off = (int)(l4 - pkt) + 8;
        out->payload_len = l4_len - 8;

        if ((out->src_port == 53 || out->dst_port == 53) &&
            out->payload_len > 12) {
            const u_char *dp = pkt + out->payload_off;
            int end = dns_read_name(dp,
                                    out->payload_len,
                                    12,
                                    out->dns_qname,
                                    sizeof(out->dns_qname));
            out->dns_qtype = (end + 1 < out->payload_len) ? dp[end + 1] : 0;
            out->has_dns   = 1;
        }

    } else if (out->l4_proto == IPPROTO_ICMP) {
        if (l4_len < 8) {
            return -1;
        }

        out->src_port    = l4[0];
        out->dst_port    = l4[1];
        out->payload_off = (int)(l4 - pkt) + 8;
        out->payload_len = l4_len - 8;

    } else {
        return -1;
    }

    if (out->payload_len < 0) {
        out->payload_len = 0;
    }

    out->flow_id = build_flow_id(out->src_ip,
                                 out->dst_ip,
                                 out->src_port,
                                 out->dst_port,
                                 out->l4_proto);

    uint32_t lo_ip = (out->src_ip < out->dst_ip ||
                     (out->src_ip == out->dst_ip &&
                      out->src_port <= out->dst_port))
                     ? out->src_ip
                     : out->dst_ip;

    out->is_fwd = (out->src_ip == lo_ip) ? 1 : 0;

    return 0;
}

/* flow lookup / creation */

static flow_entry_t *flow_lookup_or_create(const parsed_packet_t *p,
                                           double now)
{
    uint32_t idx = flow_bucket_index(p->flow_id);
    flow_bucket_t *bucket = &g_flow_table[idx];

    pthread_rwlock_rdlock(&bucket->lock);
    for (flow_entry_t *f = bucket->head; f; f = f->next) {
        if (f->flow_id == p->flow_id && !f->being_removed) {
            pthread_mutex_lock(&f->lock);
            pthread_rwlock_unlock(&bucket->lock);
            return f;
        }
    }
    pthread_rwlock_unlock(&bucket->lock);

    if (atomic_load(&g_flow_count) >= MAX_FLOWS) {
        return NULL;
    }

    flow_entry_t *nf = flow_pool_alloc();
    if (!nf) {
        return NULL;
    }

    nf->flow_id      = p->flow_id;
    nf->src_ip       = p->src_ip;
    nf->dst_ip       = p->dst_ip;
    nf->src_port     = p->src_port;
    nf->dst_port     = p->dst_port;
    nf->l4_proto     = p->l4_proto;
    nf->first_seen   = now;
    nf->last_seen    = now;
    nf->last_alert_time = 0.0;
    nf->needs_rescore   = 0;
    nf->being_removed   = 0;
    pthread_mutex_init(&nf->lock, NULL);

    pthread_rwlock_wrlock(&bucket->lock);
    for (flow_entry_t *f = bucket->head; f; f = f->next) {
        if (f->flow_id == p->flow_id && !f->being_removed) {
            pthread_mutex_lock(&f->lock);
            pthread_rwlock_unlock(&bucket->lock);
            flow_pool_free(nf);
            return f;
        }
    }

    nf->next = bucket->head;
    bucket->head = nf;
    atomic_fetch_add(&g_flow_count, 1);

    pthread_mutex_lock(&nf->lock);
    pthread_rwlock_unlock(&bucket->lock);

    return nf;
}

/* generic helpers */

static double entropy_from_hist(const int *h, int bins, int total)
{
    if (total <= 0) {
        return 0.0;
    }

    double H   = 0.0;
    double inv = 1.0 / (double)total;

    for (int i = 0; i < bins; i++) {
        if (!h[i]) {
            continue;
        }
        double p = h[i] * inv;
        H -= p * log2(p);
    }

    return H;
}

static double payload_entropy(const u_char *data, int len)
{
    if (len <= 0) {
        return 0.0;
    }

    int hist[256] = {0};
    for (int i = 0; i < len; i++) {
        hist[data[i]]++;
    }

    return entropy_from_hist(hist, 256, len);
}

/* variance over window with slot_valid mask */

static double window_variance(const void *arr,
                              const uint8_t *valid,
                              int n,
                              int is_u32,
                              double *mean_out)
{
    double mean = 0.0;
    double var  = 0.0;
    int    cnt  = 0;

    for (int i = 0; i < n; i++) {
        if (!valid[i]) {
            continue;
        }

        double v = is_u32
                 ? ((const uint32_t *)arr)[i]
                 : ((const uint16_t *)arr)[i];

        mean += v;
        cnt++;
    }

    if (cnt < 2) {
        *mean_out = mean;
        return 0.0;
    }

    mean /= (double)cnt;

    for (int i = 0; i < n; i++) {
        if (!valid[i]) {
            continue;
        }

        double v = is_u32
                 ? ((const uint32_t *)arr)[i]
                 : ((const uint16_t *)arr)[i];

        double d = v - mean;
        var += d * d;
    }

    *mean_out = mean;
    return var / (double)cnt;
}

/* burst regularity */

static double burst_score_from_ipd(const double *ipds, int n)
{
    if (n < 8) {
        return 0.0;
    }

    double mean = 0.0;
    for (int i = 0; i < n; i++) {
        mean += ipds[i];
    }
    mean /= (double)n;

    if (mean < 1e-9) {
        return 0.8;
    }

    double var = 0.0;
    for (int i = 0; i < n; i++) {
        double d = ipds[i] - mean;
        var += d * d;
    }

    double cvar = sqrt(var / (double)n) / mean;

    if (cvar < 0.10) return 0.85;
    if (cvar < 0.25) return 0.55;
    if (cvar < 0.50) return 0.30;
    return 0.05;
}

/* IP-ID delta scoring */

static double ipid_delta_channel(const uint16_t *ip_ids,
                                 const uint8_t  *valid,
                                 int n)
{
    uint16_t deltas[FLOW_WINDOW_SIZE];
    int dc = 0;

    for (int i = 1; i < n; i++) {
        if (!valid[i] || !valid[i - 1]) {
            continue;
        }
        deltas[dc++] = (uint16_t)(ip_ids[i] - ip_ids[i - 1]);
    }

    if (dc < 8) {
        return 0.0;
    }

    double mean = 0.0;
    for (int i = 0; i < dc; i++) {
        mean += deltas[i];
    }
    mean /= (double)dc;

    double var = 0.0;
    for (int i = 0; i < dc; i++) {
        double d = deltas[i] - mean;
        var += d * d;
    }

    double std = sqrt(var / (double)dc);

    if (std < 1.0)                         return 0.55;
    if (std < 8.0 && mean < 8.0)           return 0.60;
    if (std < 3.0 && mean > 0.5 && mean < 5.0) return 0.10;
    return 0.05;
}

/* scoring logic */

static void compute_flow_scores(flow_entry_t *f,
                                const u_char *raw,
                                int caplen,
                                const parsed_packet_t *p)
{
    if (f->pkt_count < MIN_PACKETS_FOR_SCORE) {
        return;
    }

    if (!f->needs_rescore) {
        return;
    }

    f->needs_rescore = 0;

    memset(f->channel_score, 0, sizeof(f->channel_score));
    f->composite_score = 0.0;

    int n = (f->pkt_count < FLOW_WINDOW_SIZE)
          ? (int)f->pkt_count
          : FLOW_WINDOW_SIZE;

    feature_vec_t *ft = &f->features;

    /* channel 0 + 10: IPD CoV + burstiness */

    {
        double ipds[FLOW_WINDOW_SIZE];
        int    valid = 0;
        double mean  = 0.0;
        double var   = 0.0;

        for (int i = 1; i < n; i++) {
            double d = f->times[i] - f->times[i - 1];
            if (d > 0.0) {
                ipds[valid++] = d;
                mean += d;
            }
        }

        if (valid > 4) {
            mean /= (double)valid;
            for (int i = 0; i < valid; i++) {
                double d = ipds[i] - mean;
                var += d * d;
            }

            ft->ipd_mean = mean;
            ft->ipd_std  = sqrt(var / (double)valid);
            ft->ipd_cvar = (mean > 1e-9) ? (ft->ipd_std / mean) : 0.0;

            if      (ft->ipd_cvar < 0.10) f->channel_score[0] = 0.85;
            else if (ft->ipd_cvar < 0.25) f->channel_score[0] = 0.55;
            else if (ft->ipd_cvar < 0.50) f->channel_score[0] = 0.25;
            else                          f->channel_score[0] = 0.05;

            ft->burst_score       = burst_score_from_ipd(ipds, valid);
            f->channel_score[10]  = ft->burst_score;
        }
    }

    /* channel 1: length variability */

    {
        double mean = 0.0;
        double var  = 0.0;

        for (int i = 0; i < n; i++) {
            mean += f->lengths[i];
        }
        mean /= (double)n;

        for (int i = 0; i < n; i++) {
            double d = f->lengths[i] - mean;
            var += d * d;
        }

        ft->len_mean = mean;
        ft->len_std  = sqrt(var / (double)n);

        if      (ft->len_std < 2.0)  f->channel_score[1] = 0.85;
        else if (ft->len_std < 10.0) f->channel_score[1] = 0.60;
        else if (ft->len_std < 30.0) f->channel_score[1] = 0.30;
        else                         f->channel_score[1] = 0.05;
    }

    /* channel 2: protocol entropy */

    {
        int hist[256] = {0};
        for (int i = 0; i < n; i++) {
            hist[f->protocols[i]]++;
        }

        ft->proto_entropy   = entropy_from_hist(hist, 256, n);
        f->channel_score[2] = (ft->proto_entropy > 0.1) ? 0.30 : 0.05;
    }

    /* channel 3: TCP flag entropy */

    {
        int hist[256] = {0};
        int total     = 0;

        for (int i = 0; i < n; i++) {
            if (f->flags[i]) {
                hist[(uint8_t)f->flags[i]]++;
                total++;
            }
        }

        ft->flag_entropy = entropy_from_hist(hist, 256, total);

        if      (ft->flag_entropy > 1.5) f->channel_score[3] = 0.70;
        else if (ft->flag_entropy > 0.8) f->channel_score[3] = 0.40;
        else                             f->channel_score[3] = 0.05;
    }

    /* channels 4-6: seq/ack/window variance */

    if (f->l4_proto == IPPROTO_TCP) {
        double tmp_mean;

        ft->seq_var = window_variance(f->seqs,
                                      f->slot_valid,
                                      n,
                                      1,
                                      &tmp_mean);
        ft->ack_var = window_variance(f->acks,
                                      f->slot_valid,
                                      n,
                                      1,
                                      &tmp_mean);
        ft->win_var = window_variance(f->win_sizes,
                                      f->slot_valid,
                                      n,
                                      0,
                                      &tmp_mean);

        f->channel_score[4] = (ft->seq_var    < 1e6) ? 0.40 : 0.10;
        f->channel_score[5] = (ft->ack_var    < 1e6) ? 0.40 : 0.10;
        f->channel_score[6] = (ft->win_var    < 1e4) ? 0.40 : 0.10;
    }

    /* channel 5 override: IP-ID delta */

    {
        double s = ipid_delta_channel(f->ip_ids, f->slot_valid, n);
        ft->ipid_score = s;
        if (s > f->channel_score[5]) {
            f->channel_score[5] = s;
        }
    }

    /* channel 7: TTL variance */

    {
        double mean = 0.0;
        double var  = 0.0;

        for (int i = 0; i < n; i++) {
            mean += f->ttls[i];
        }
        mean /= (double)n;

        for (int i = 0; i < n; i++) {
            double d = f->ttls[i] - mean;
            var += d * d;
        }

        ft->ttl_var = var / (double)n;

        if      (ft->ttl_var > 10.0) f->channel_score[7] = 0.60;
        else if (ft->ttl_var > 2.0)  f->channel_score[7] = 0.30;
        else                         f->channel_score[7] = 0.05;
    }

    /* channel 8: payload entropy + DNS tunnel */

    {
        double pe = 0.0;

        if (raw &&
            p->payload_len > 8 &&
            p->payload_off + p->payload_len <= caplen) {

            ft->payload_entropy = payload_entropy(raw + p->payload_off,
                                                  p->payload_len);

            if      (ft->payload_entropy > 7.5) pe = 0.60;
            else if (ft->payload_entropy > 6.0) pe = 0.30;
            else                                pe = 0.05;
        }

        if (f->dns_state.score > pe) {
            pe = f->dns_state.score;
        }

        f->channel_score[8] = pe;
    }

    /* channel 9: directional asymmetry */

    {
        uint64_t total = f->bytes_fwd + f->bytes_rev;
        if (total > 0) {
            double r = (double)f->bytes_fwd / (double)total;
            ft->asymmetry_ratio = fabs(r - 0.5) * 2.0;

            if      (ft->asymmetry_ratio > 0.85) f->channel_score[9] = 0.55;
            else if (ft->asymmetry_ratio > 0.60) f->channel_score[9] = 0.25;
            else                                 f->channel_score[9] = 0.05;
        }
    }

    /* channel 11: retransmission rate */

    {
        double rr = (f->pkt_count > 0)
                  ? (double)f->retrans_count / (double)f->pkt_count
                  : 0.0;

        if      (rr > 0.15) f->channel_score[11] = 0.50;
        else if (rr > 0.05) f->channel_score[11] = 0.25;
        else                f->channel_score[11] = 0.05;
    }

    /* weighted composite */

    static const double W[FEATURE_CHANNELS] = {
        2.0, 2.0, 0.5, 1.5,
        1.0, 1.5, 1.0, 1.0,
        2.0, 1.5, 2.0, 1.0
    };

    double ws = 0.0;
    double wt = 0.0;

    for (int i = 0; i < FEATURE_CHANNELS; i++) {
        ws += f->channel_score[i] * W[i];
        wt += W[i];
    }

    f->composite_score = (wt > 0.0) ? (ws / wt) : 0.0;
}

/* alert output */

static void emit_alert(const flow_entry_t *f,
                       const parsed_packet_t *p __attribute__((unused)))
{
    char src_str[INET_ADDRSTRLEN];
    char dst_str[INET_ADDRSTRLEN];
    struct in_addr a;

    a.s_addr = htonl(f->src_ip);
    inet_ntop(AF_INET, &a, src_str, sizeof(src_str));

    a.s_addr = htonl(f->dst_ip);
    inet_ntop(AF_INET, &a, dst_str, sizeof(dst_str));

    const char *proto =
        (f->l4_proto == IPPROTO_TCP) ? "TCP" :
        (f->l4_proto == IPPROTO_UDP) ? "UDP" :
                                       "ICMP";

    atomic_fetch_add(&g_alert_count, 1);

    if (g_cfg.json_output) {
        printf(
            "{\"alert\":true,"
            "\"score\":%.4f,"
            "\"flow_id\":\"%016llx\","
            "\"src\":\"%s\","
            "\"dst\":\"%s\","
            "\"sport\":%u,"
            "\"dport\":%u,"
            "\"proto\":\"%s\","
            "\"pkts\":%llu,"
            "\"bytes_fwd\":%llu,"
            "\"bytes_rev\":%llu,"
            "\"frags\":%u,"
            "\"icmp\":%u,"
            "\"dns_score\":%.3f,"
            "\"ipid_score\":%.3f,"
            "\"ch\":[%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,"
                     "%.3f,%.3f,%.3f,%.3f,%.3f,%.3f]}\n",
            f->composite_score,
            (unsigned long long)f->flow_id,
            src_str,
            dst_str,
            (unsigned)f->src_port,
            (unsigned)f->dst_port,
            proto,
            (unsigned long long)f->pkt_count,
            (unsigned long long)f->bytes_fwd,
            (unsigned long long)f->bytes_rev,
            f->fragment_count,
            f->icmp_count,
            f->dns_state.score,
            f->features.ipid_score,
            f->channel_score[0],  f->channel_score[1],
            f->channel_score[2],  f->channel_score[3],
            f->channel_score[4],  f->channel_score[5],
            f->channel_score[6],  f->channel_score[7],
            f->channel_score[8],  f->channel_score[9],
            f->channel_score[10], f->channel_score[11]
        );
    } else {
        printf("\nALERT [%.3f] %s:%u -> %s:%u | %s | pkts=%llu frags=%u icmp=%u\n",
               f->composite_score,
               src_str, (unsigned)f->src_port,
               dst_str, (unsigned)f->dst_port,
               proto,
               (unsigned long long)f->pkt_count,
               f->fragment_count,
               f->icmp_count);

        printf("  Timing=%.2f Len=%.2f Flags=%.2f Payload=%.2f "
               "Burst=%.2f Asym=%.2f TTL=%.2f Retrans=%.2f\n",
               f->channel_score[0],
               f->channel_score[1],
               f->channel_score[3],
               f->channel_score[8],
               f->channel_score[10],
               f->channel_score[9],
               f->channel_score[7],
               f->channel_score[11]);

        if (f->dns_state.score > 0.0) {
            printf("  DNS tunnel score=%.2f qrate=%u txt/null=%u enc=%u\n",
                   f->dns_state.score,
                   f->dns_state.window_queries,
                   f->dns_state.txt_or_null_count,
                   f->dns_state.encoded_label_count);
        }

        if (f->features.ipid_score > 0.0) {
            printf("  IP-ID channel score=%.2f\n", f->features.ipid_score);
        }

        if (g_cfg.verbose) {
            printf("  ipd_cvar=%.3f len_std=%.1f ttl_var=%.1f "
                   "payload_H=%.2f asym=%.2f retrans=%u\n",
                   f->features.ipd_cvar,
                   f->features.len_std,
                   f->features.ttl_var,
                   f->features.payload_entropy,
                   f->features.asymmetry_ratio,
                   f->retrans_count);
        }
    }

    fflush(stdout);
}

/* packet processing */

static void process_packet(const ring_packet_t *rp)
{
    parsed_packet_t p;

    if (parse_packet(rp->data, (int)rp->hdr.caplen, &p) < 0) {
        return;
    }

    double ts;
    if (g_cfg.use_nano_ts) {
        ts = (double)rp->hdr.ts.tv_sec +
             (double)rp->hdr.ts.tv_usec * 1e-9;
    } else {
        ts = (double)rp->hdr.ts.tv_sec +
             (double)rp->hdr.ts.tv_usec * 1e-6;
    }

    flow_entry_t *f = flow_lookup_or_create(&p, ts);
    if (!f) {
        return;
    }

    if (f->being_removed) {
        pthread_mutex_unlock(&f->lock);
        return;
    }

    if (p.is_fragment) {
        f->fragment_count++;
        pthread_mutex_unlock(&f->lock);
        return;
    }

    if (p.l4_proto == IPPROTO_ICMP) {
        f->icmp_count++;
        f->pkt_count++;
        f->last_seen = ts;
        pthread_mutex_unlock(&f->lock);
        return;
    }

    int idx = (int)(f->pkt_count % FLOW_WINDOW_SIZE);

    /* retransmission check */

    if (p.l4_proto == IPPROTO_TCP && p.seq != 0) {
        if (seq_cache_has(&f->seq_cache, p.seq)) {
            f->retrans_count++;
        } else {
            seq_cache_add(&f->seq_cache, p.seq);
        }

        if (f->pkt_count > 0 &&
            (f->pkt_count % SEQ_CACHE_SIZE) == 0) {
            seq_cache_reset(&f->seq_cache);
        }
    }

    /* DNS heuristics */

    if (p.has_dns) {
        dns_tunnel_score(&f->dns_state,
                         ts,
                         p.dns_qname,
                         p.dns_qtype);
    }

    /* write window slot */

    f->times[idx]      = ts;
    f->lengths[idx]    = p.pkt_len;
    f->protocols[idx]  = p.l4_proto;
    f->flags[idx]      = p.tcp_flags;
    f->ttls[idx]       = p.ttl;
    f->seqs[idx]       = p.seq;
    f->acks[idx]       = p.ack;
    f->win_sizes[idx]  = p.win;
    f->ip_ids[idx]     = p.ip_id;
    f->slot_valid[idx] = 1;

    if (p.is_fwd) {
        f->bytes_fwd += p.pkt_len;
    } else {
        f->bytes_rev += p.pkt_len;
    }

    f->pkt_count++;
    f->last_seen = ts;

    if ((f->pkt_count % RESCORE_STEP) == 0) {
        f->needs_rescore = 1;
    }

    compute_flow_scores(f, rp->data, (int)rp->hdr.caplen, &p);

    if (f->composite_score > g_cfg.score_threshold &&
        f->pkt_count > MIN_PACKETS_FOR_ALERT &&
        (ts - f->last_alert_time) >= g_cfg.alert_cooldown) {

        emit_alert(f, &p);
        f->last_alert_time = ts;
    }

    pthread_mutex_unlock(&f->lock);
}

/* worker thread */

static void *worker_thread(void *arg)
{
    (void)arg;

#ifdef __linux__
    if (g_cfg.worker_core >= 0) {
        cpu_set_t cs;
        CPU_ZERO(&cs);
        CPU_SET(g_cfg.worker_core, &cs);
        pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
    }
#endif

    while (g_running) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += 10000000;
        if (ts.tv_nsec >= 1000000000L) {
            ts.tv_sec++;
            ts.tv_nsec -= 1000000000L;
        }

        sem_timedwait(&g_ring_sem, &ts);

        while (1) {
            uint64_t h = atomic_load_explicit(&g_ring.head,
                                              memory_order_acquire);
            uint64_t t = atomic_load_explicit(&g_ring.tail,
                                              memory_order_relaxed);

            if (t == h) {
                break;
            }

            process_packet(&g_ring.slots[t & RING_BUFFER_MASK]);
            atomic_store_explicit(&g_ring.tail,
                                  t + 1,
                                  memory_order_release);
        }
    }

    /* drain remaining packets */

    uint64_t h = atomic_load(&g_ring.head);
    uint64_t t = atomic_load(&g_ring.tail);

    while (t != h) {
        process_packet(&g_ring.slots[t & RING_BUFFER_MASK]);
        t++;
    }

    return NULL;
}

/* capture callback */

void capture_callback(u_char *user,
                      const struct pcap_pkthdr *hdr,
                      const u_char *data)
{
    (void)user;

    uint64_t h = atomic_load_explicit(&g_ring.head,
                                      memory_order_relaxed);
    uint64_t t = atomic_load_explicit(&g_ring.tail,
                                      memory_order_acquire);

    if (h - t >= RING_BUFFER_SIZE) {
        atomic_fetch_add(&g_ring.dropped, 1);
        return;
    }

    ring_packet_t *slot = &g_ring.slots[h & RING_BUFFER_MASK];

    slot->hdr = *hdr;
    uint32_t cap = (hdr->caplen < CAPTURE_SNAPLEN)
                 ? hdr->caplen
                 : (uint32_t)CAPTURE_SNAPLEN;

    memcpy(slot->data, data, cap);
    slot->hdr.caplen = cap;

    atomic_store_explicit(&g_ring.head,
                          h + 1,
                          memory_order_release);

    int val = 0;
    sem_getvalue(&g_ring_sem, &val);
    if (val == 0) {
        sem_post(&g_ring_sem);
    }
}

/* cleanup thread: remove idle/old flows */

static void *cleanup_thread(void *arg)
{
    (void)arg;

#ifdef __linux__
    if (g_cfg.cleanup_core >= 0) {
        cpu_set_t cs;
        CPU_ZERO(&cs);
        CPU_SET(g_cfg.cleanup_core, &cs);
        pthread_setaffinity_np(pthread_self(), sizeof(cs), &cs);
    }
#endif

    while (g_running) {
        sleep(30);

        double now = (double)time(NULL);
        int freed  = 0;

        for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
            flow_bucket_t *bucket = &g_flow_table[i];

            pthread_rwlock_wrlock(&bucket->lock);

            flow_entry_t *prev = NULL;
            flow_entry_t *f    = bucket->head;

            while (f) {
                int idle_expired =
                    (now - f->last_seen) > g_cfg.idle_timeout;
                int life_expired =
                    (now - f->first_seen) > g_cfg.max_lifetime;

                if (idle_expired || life_expired) {
                    f->being_removed = 1;
                    pthread_mutex_lock(&f->lock);

                    flow_entry_t *to_free = f;

                    if (prev) {
                        prev->next = f->next;
                    } else {
                        bucket->head = f->next;
                    }

                    f = f->next;

                    pthread_mutex_unlock(&to_free->lock);
                    flow_pool_free(to_free);
                    atomic_fetch_sub(&g_flow_count, 1);
                    freed++;
                    continue;
                }

                prev = f;
                f    = f->next;
            }

            pthread_rwlock_unlock(&bucket->lock);
        }

        if (g_cfg.verbose && freed > 0) {
            fprintf(stderr, "[cleanup] freed %d flows\n", freed);
        }
    }

    return NULL;
}

/* signal handler */

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
    sem_post(&g_ring_sem);
}

/* initialization */

static void init_flow_table(void)
{
    for (int i = 0; i < FLOW_TABLE_SIZE; i++) {
        g_flow_table[i].head = NULL;
        pthread_rwlock_init(&g_flow_table[i].lock, NULL);
    }
}

static void init_ring(void)
{
    memset(&g_ring, 0, sizeof(g_ring));
    sem_init(&g_ring_sem, 0, 0);
}

/* argument parsing (minimal) */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -i <iface>|-r <pcap> [options]\n"
            "  -i <iface>     live interface\n"
            "  -r <file>      read from pcap file\n"
            "  -t <thresh>    score threshold (default %.2f)\n"
            "  -j             JSON output\n"
            "  -v             verbose\n",
            prog,
            DEFAULT_SCORE_THRESHOLD);
}

static int parse_args(int argc, char **argv)
{
    int opt;
    int have_source = 0;

    while ((opt = getopt(argc, argv, "i:r:t:jv")) != -1) {
        switch (opt) {
        case 'i':
            g_cfg.iface_or_file = optarg;
            have_source = 1;
            break;
        case 'r':
            g_cfg.iface_or_file = optarg;
            have_source = 1;
            break;
        case 't':
            g_cfg.score_threshold = atof(optarg);
            break;
        case 'j':
            g_cfg.json_output = 1;
            break;
        case 'v':
            g_cfg.verbose = 1;
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (!have_source) {
        usage(argv[0]);
        return -1;
    }

    return 0;
}

/* main */

int main(int argc, char **argv)
{
    if (parse_args(argc, argv) < 0) {
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pc = NULL;

    /* decide live vs offline based on whether file exists or iface name */
    struct stat st;
    if (stat(g_cfg.iface_or_file, &st) == 0 && S_ISREG(st.st_mode)) {
        pc = pcap_open_offline(g_cfg.iface_or_file, errbuf);
    } else {
        pc = pcap_open_live(g_cfg.iface_or_file,
                            CAPTURE_SNAPLEN,
                            g_cfg.promiscuous,
                            1000,
                            errbuf);
    }

    if (!pc) {
        fprintf(stderr, "pcap open failed: %s\n", errbuf);
        return 1;
    }

    if (pcap_set_buffer_size(pc, KERNEL_RING_BYTES) != 0) {
        fprintf(stderr, "warning: could not set kernel buffer size\n");
    }

    flow_pool_init();
    init_flow_table();
    init_ring();

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    pthread_t worker_tid;
    pthread_t cleanup_tid;

    if (pthread_create(&worker_tid, NULL, worker_thread, NULL) != 0) {
        fprintf(stderr, "failed to start worker thread\n");
        pcap_close(pc);
        return 1;
    }

    if (pthread_create(&cleanup_tid, NULL, cleanup_thread, NULL) != 0) {
        fprintf(stderr, "failed to start cleanup thread\n");
        g_running = 0;
        sem_post(&g_ring_sem);
        pthread_join(worker_tid, NULL);
        pcap_close(pc);
        return 1;
    }

    if (pcap_loop(pc, -1, capture_callback, NULL) < 0) {
        fprintf(stderr, "pcap_loop error: %s\n", pcap_geterr(pc));
    }

    g_running = 0;
    sem_post(&g_ring_sem);

    pthread_join(worker_tid, NULL);
    pthread_join(cleanup_tid, NULL);

    pcap_close(pc);
    return 0;
}

- Tune the scoring weights/thresholds for fewer FPs on your real traces.
- Strip it down further (e.g., remove JSON, remove some channels) to make it look even more “hand-written” and less like a research artifact.
