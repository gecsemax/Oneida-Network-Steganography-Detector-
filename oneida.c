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

/* ============================================================
 * Oneida v4.2
 * 12-Channel Network Steganography Detector
 *
 * Fixed vs v4.1:
 *   [B1] Ch7 TTL direction corrected: high var = suspicious
 *   [B2] slot_valid[] now used in window_variance (no v==0 skip)
 *   [B3] Cleanup deadlock fixed: bucket lock released before mutex
 *   [B4] pool_free_head/tail changed to uint32_t (overflow fix)
 *   [B5] Source detection uses stat() instead of strstr
 *   [B6] sem_post capped with sem_getvalue guard
 *   [B7] ICMP support added (BPF + parser + flow tracking)
 *   [B8] Dirty flag: full rescore every WINDOW_SIZE/4 packets
 *   [B9] SIGUSR1 live stats handler
 *   [B10] IP-ID delta channel (Ch 5 now implemented)
 *   [B11] DNS tunnel: charset + rate + record type heuristics
 *   [B12] g_alert_count atomic counter, printed on exit
 * ============================================================ */

/* ── Constants ── */
#ifndef MAX_FLOWS
#  define MAX_FLOWS         32768
#endif
#ifndef FLOW_HASH_SIZE
#  define FLOW_HASH_SIZE    8192
#endif
#ifndef WINDOW_SIZE
#  define WINDOW_SIZE       256
#endif
#define NUM_CHANNELS        12
#define RING_CAPACITY       65536
#define RING_MASK           (RING_CAPACITY - 1)
#define DEFAULT_THRESH      0.45
#define DEFAULT_IDLE        300
#define DEFAULT_MAXLIFE     3600
#define DEFAULT_COOLDOWN    5.0
#define SNAPLEN             9216
#define MIN_SCORE_PKTS      20
#define ALERT_PKT_MIN       30
#define L2_LEN              14
#define SEQ_SET_BITS        9
#define SEQ_SET_SIZE        (1 << SEQ_SET_BITS)
#define SEQ_SET_MASK        (SEQ_SET_SIZE - 1)
#define KERNEL_RING_BYTES   (64 * 1024 * 1024)
#define RESCORE_INTERVAL    (WINDOW_SIZE / 4)
#define DNS_RATE_WINDOW     10.0
#define DNS_RATE_THRESH     10

/* ── [F4] Open-addressed SEQ hash set ── */
typedef struct {
    uint32_t keys[SEQ_SET_SIZE];
    uint8_t  used[SEQ_SET_SIZE];
} seq_set_t;

static inline int seq_set_contains(const seq_set_t *s, uint32_t seq)
{
    uint32_t slot = seq & SEQ_SET_MASK;
    return s->used[slot] && s->keys[slot] == seq;
}
static inline void seq_set_insert(seq_set_t *s, uint32_t seq)
{
    uint32_t slot = seq & SEQ_SET_MASK;
    s->keys[slot] = seq;
    s->used[slot] = 1;
}
static inline void seq_set_clear(seq_set_t *s)
{
    memset(s->used, 0, sizeof s->used);
}

/* ── [B11] DNS tunnel heuristics state ── */
typedef struct {
    uint32_t query_count;
    uint32_t txt_null_count;
    uint32_t b32b64_count;
    uint32_t long_label_count;
    double   window_start;
    uint32_t window_queries;
    double   dns_score;
} dns_state_t;

static int looks_encoded(const char *s)
{
    int len = (int)strlen(s);
    if (len < 16) return 0;
    int b32 = 0, b64 = 0;
    for (int i = 0; i < len; i++) {
        char c = s[i];
        if ((c>='A'&&c<='Z')||(c>='2'&&c<='7')||c=='=') b32++;
        if ((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')
            ||c=='+'||c=='/'||c=='=') b64++;
    }
    return (b32*100/len > 80) || (b64*100/len > 85);
}

static double compute_dns_tunnel_score(dns_state_t *ds, double now,
                                       const char *qname, uint8_t qtype)
{
    ds->query_count++;
    if (now - ds->window_start > DNS_RATE_WINDOW) {
        ds->window_start   = now;
        ds->window_queries = 0;
    }
    ds->window_queries++;
    if (qtype == 16 || qtype == 10) ds->txt_null_count++;

    char copy[256]; strncpy(copy, qname, 255); copy[255] = '\0';
    char *tok = copy, *p = copy;
    while (*p) {
        if (*p == '.') {
            *p = '\0';
            int ll = (int)strlen(tok);
            if (ll > 40) ds->long_label_count++;
            if (looks_encoded(tok)) ds->b32b64_count++;
            tok = p + 1;
        }
        p++;
    }
    int ll = (int)strlen(tok);
    if (ll > 40) ds->long_label_count++;
    if (looks_encoded(tok)) ds->b32b64_count++;

    double score = 0.0;
    if (ds->window_queries  > DNS_RATE_THRESH) score += 0.40;
    if (ds->txt_null_count  > 2)               score += 0.30;
    if (ds->b32b64_count    > 2)               score += 0.35;
    if (ds->long_label_count > 1)              score += 0.25;
    if (score > 0.90) score = 0.90;
    ds->dns_score = score;
    return score;
}

/* ── Configuration ── */
typedef struct {
    const char *source;
    double      thresh;
    double      alert_cooldown;
    int         idle_timeout;
    int         max_life;
    int         json_output;
    int         promiscuous;
    int         worker_core;
    int         cleanup_core;
    int         verbose;
    int         nano_ts;
} config_t;

static config_t g_cfg = {
    .thresh         = DEFAULT_THRESH,
    .alert_cooldown = DEFAULT_COOLDOWN,
    .idle_timeout   = DEFAULT_IDLE,
    .max_life       = DEFAULT_MAXLIFE,
    .json_output    = 0,
    .promiscuous    = 1,
    .worker_core    = -1,
    .cleanup_core   = -1,
    .verbose        = 0,
    .nano_ts        = 0,
};

/* ── ML feature vector ── */
typedef struct {
    double ipd_mean, ipd_std, ipd_cvar;
    double len_mean, len_std;
    double proto_entropy, flag_entropy;
    double seq_var, ack_var, window_var;
    double ttl_var;
    double ipid_delta_var;
    double payload_entropy;
    double burst_score, asymmetry_ratio;
    int    retrans_count;
} ml_features_t;

/* ── Flow record ── */
typedef struct flow_t flow_t;

struct flow_t {
    uint64_t flow_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint8_t  l4_proto;

    double   times[WINDOW_SIZE];
    uint16_t lengths[WINDOW_SIZE];
    uint8_t  protocols[WINDOW_SIZE];
    uint8_t  flags[WINDOW_SIZE];
    uint8_t  ttls[WINDOW_SIZE];
    uint32_t seqs[WINDOW_SIZE];
    uint32_t acks[WINDOW_SIZE];
    uint16_t win_sizes[WINDOW_SIZE];
    uint16_t ip_ids[WINDOW_SIZE];
    uint8_t  slot_valid[WINDOW_SIZE];

    seq_set_t   seen_seqs;
    dns_state_t dns;

    uint64_t bytes_fwd, bytes_rev;
    uint64_t pkt_count;
    uint32_t retrans_count;
    uint32_t fragment_count;
    uint32_t icmp_count;

    double        channel_scores[NUM_CHANNELS];
    double        composite_score;
    ml_features_t features;

    double first_seen, last_seen;
    double last_alerted;
    int    dirty;

    volatile int    deleting;
    pthread_mutex_t lock;
    flow_t         *next;
    int             pool_idx;
};

/* ── [B4] Slab pool — uint32_t counters ── */
static flow_t    g_pool[MAX_FLOWS];
static uint8_t   g_pool_used[MAX_FLOWS];
static uint32_t  g_pool_freelist[MAX_FLOWS];
static uint32_t  g_pool_free_head = 0;
static uint32_t  g_pool_free_tail = 0;
static pthread_mutex_t g_pool_lock = PTHREAD_MUTEX_INITIALIZER;

static void pool_init(void)
{
    for (int i = 0; i < MAX_FLOWS; i++) {
        g_pool_freelist[i] = (uint32_t)i;
        g_pool_used[i] = 0;
    }
    g_pool_free_head = 0;
    g_pool_free_tail = (uint32_t)MAX_FLOWS;
}

static flow_t *pool_alloc(void)
{
    pthread_mutex_lock(&g_pool_lock);
    if (g_pool_free_head == g_pool_free_tail) {
        pthread_mutex_unlock(&g_pool_lock);
        return NULL;
    }
    int idx = (int)(g_pool_freelist[g_pool_free_head % MAX_FLOWS]);
    g_pool_free_head++;
    g_pool_used[idx] = 1;
    pthread_mutex_unlock(&g_pool_lock);
    memset(&g_pool[idx], 0, sizeof(flow_t));
    g_pool[idx].pool_idx = idx;
    return &g_pool[idx];
}

static void pool_free(flow_t *f)
{
    int idx = f->pool_idx;
    pthread_mutex_lock(&g_pool_lock);
    g_pool_used[idx] = 0;
    g_pool_freelist[g_pool_free_tail % MAX_FLOWS] = (uint32_t)idx;
    g_pool_free_tail++;
    pthread_mutex_unlock(&g_pool_lock);
}

/* ── Hash table ── */
typedef struct {
    flow_t          *head;
    pthread_rwlock_t rwlock;
} hash_bucket_t;

static hash_bucket_t g_table[FLOW_HASH_SIZE];
static atomic_int    g_flow_count = 0;
static volatile int  g_running    = 1;

/* [B12] */
static atomic_uint_least64_t g_alert_count = 0;

/* ── Ring buffer ── */
typedef struct {
    struct pcap_pkthdr hdr;
    u_char             data[SNAPLEN];
} ring_pkt_t;

typedef struct {
    ring_pkt_t            slots[RING_CAPACITY];
    atomic_uint_least64_t head;
    atomic_uint_least64_t tail;
    atomic_uint_least64_t dropped;
} ring_t;

static ring_t g_ring;
static sem_t  g_ring_sem;

/* ── Hash helpers ── */
static inline uint64_t mix64(uint64_t x)
{
    x ^= x >> 33; x *= UINT64_C(0xff51afd7ed558ccd);
    x ^= x >> 33; x *= UINT64_C(0xc4ceb9fe1a85ec53);
    x ^= x >> 33; return x;
}
static inline uint32_t bucket_idx(uint64_t id)
{
    return (uint32_t)(mix64(id) & (FLOW_HASH_SIZE - 1));
}
static inline uint64_t make_flow_id(uint32_t sip, uint32_t dip,
                                    uint16_t sp, uint16_t dp, uint8_t proto)
{
    uint32_t lo_ip, hi_ip; uint16_t lo_pt, hi_pt;
    if (sip < dip || (sip == dip && sp <= dp))
        { lo_ip=sip; hi_ip=dip; lo_pt=sp; hi_pt=dp; }
    else
        { lo_ip=dip; hi_ip=sip; lo_pt=dp; hi_pt=sp; }
    uint64_t id = (uint64_t)lo_ip | ((uint64_t)hi_ip << 32);
    id ^= ((uint64_t)lo_pt<<48)^((uint64_t)hi_pt<<56)^((uint64_t)proto<<40);
    return mix64(id);
}

/* ── DNS name decoder ── */
static int dns_decode_name(const u_char *payload, int plen,
                           int offset, char *out, int outlen)
{
    int pos = offset, written = 0, jumps = 0;
    while (pos < plen && jumps < 10) {
        uint8_t len = payload[pos];
        if (len == 0) { pos++; break; }
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= plen) break;
            pos = ((len & 0x3F) << 8) | payload[pos + 1];
            jumps++; continue;
        }
        pos++;
        if (pos + len > plen) break;
        if (written > 0 && written < outlen - 1) out[written++] = '.';
        int copy = (len < outlen - written - 1) ? len : outlen - written - 1;
        memcpy(out + written, payload + pos, copy);
        written += copy; pos += len;
    }
    out[written] = '\0';
    return pos;
}

/* ── Packet parser ── */
typedef struct {
    uint64_t flow_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port, pkt_len, win;
    uint16_t ip_id;
    uint8_t  l4_proto, ttl, tcp_flags;
    uint32_t seq, ack;
    int      payload_off, payload_len, is_fwd;
    int      is_fragment;
    char     dns_qname[256];
    uint8_t  dns_qtype;
    int      has_dns;
} parsed_pkt_t;

static int parse_packet(const u_char *pkt, int caplen, parsed_pkt_t *out)
{
    if (caplen < L2_LEN + 20) return -1;
    const u_char *ip = pkt + L2_LEN;
    if (((ip[0] >> 4) & 0xF) != 4) return -1;
    uint8_t ihl = (ip[0] & 0xF) * 4;
    if (ihl < 20 || caplen < L2_LEN + ihl) return -1;

    out->l4_proto = ip[9];
    out->pkt_len  = (uint16_t)((ip[2]<<8)|ip[3]);
    out->ttl      = ip[8];
    out->ip_id    = (uint16_t)((ip[4]<<8)|ip[5]);
    memcpy(&out->src_ip, ip+12, 4); out->src_ip = ntohl(out->src_ip);
    memcpy(&out->dst_ip, ip+16, 4); out->dst_ip = ntohl(out->dst_ip);

    uint16_t frag_field = (uint16_t)((ip[6]<<8)|ip[7]);
    out->is_fragment = ((frag_field & 0x1FFF)!=0)||((frag_field>>13)&1);

    const u_char *l4 = ip + ihl;
    int l4a = caplen - L2_LEN - ihl;
    out->tcp_flags=0; out->seq=out->ack=out->win=0;
    out->src_port=out->dst_port=0; out->has_dns=0;

    if (out->l4_proto == IPPROTO_TCP) {
        if (l4a < 20) return -1;
        uint8_t thl = ((l4[12]>>4)&0xF)*4;
        if (thl < 20 || l4a < thl) return -1;
        out->src_port  = (uint16_t)((l4[0]<<8)|l4[1]);
        out->dst_port  = (uint16_t)((l4[2]<<8)|l4[3]);
        out->seq       = (uint32_t)((l4[4]<<24)|(l4[5]<<16)|(l4[6]<<8)|l4[7]);
        out->ack       = (uint32_t)((l4[8]<<24)|(l4[9]<<16)|(l4[10]<<8)|l4[11]);
        out->tcp_flags = l4[13];
        out->win       = (uint16_t)((l4[14]<<8)|l4[15]);
        out->payload_off = (int)(l4-pkt)+thl;
        out->payload_len = l4a-thl;

    } else if (out->l4_proto == IPPROTO_UDP) {
        if (l4a < 8) return -1;
        out->src_port    = (uint16_t)((l4[0]<<8)|l4[1]);
        out->dst_port    = (uint16_t)((l4[2]<<8)|l4[3]);
        out->payload_off = (int)(l4-pkt)+8;
        out->payload_len = l4a-8;
        if ((out->src_port==53||out->dst_port==53) && out->payload_len>12) {
            const u_char *dp = pkt + out->payload_off;
            int end = dns_decode_name(dp, out->payload_len, 12,
                                      out->dns_qname, sizeof out->dns_qname);
            out->dns_qtype = (end+1 < out->payload_len) ? dp[end+1] : 0;
            out->has_dns = 1;
        }

    } else if (out->l4_proto == IPPROTO_ICMP) {
        if (l4a < 8) return -1;
        out->src_port    = l4[0];
        out->dst_port    = l4[1];
        out->payload_off = (int)(l4-pkt)+8;
        out->payload_len = l4a-8;
    } else return -1;

    if (out->payload_len < 0) out->payload_len = 0;
    out->flow_id = make_flow_id(out->src_ip,out->dst_ip,
                                out->src_port,out->dst_port,out->l4_proto);
    uint32_t lo = (out->src_ip < out->dst_ip ||
                  (out->src_ip==out->dst_ip && out->src_port<=out->dst_port))
                  ? out->src_ip : out->dst_ip;
    out->is_fwd = (out->src_ip == lo) ? 1 : 0;
    return 0;
}

/* ── Flow table ── */
static flow_t *flow_lookup_or_create(const parsed_pkt_t *p, double now)
{
    uint32_t bi = bucket_idx(p->flow_id);
    hash_bucket_t *b = &g_table[bi];

    pthread_rwlock_rdlock(&b->rwlock);
    for (flow_t *f = b->head; f; f = f->next) {
        if (f->flow_id == p->flow_id && !f->deleting) {
            pthread_mutex_lock(&f->lock);
            pthread_rwlock_unlock(&b->rwlock);
            return f;
        }
    }
    pthread_rwlock_unlock(&b->rwlock);

    if (atomic_load(&g_flow_count) >= MAX_FLOWS) return NULL;
    flow_t *nf = pool_alloc();
    if (!nf) return NULL;

    nf->flow_id    = p->flow_id;
    nf->src_ip     = p->src_ip;
    nf->dst_ip     = p->dst_ip;
    nf->src_port   = p->src_port;
    nf->dst_port   = p->dst_port;
    nf->l4_proto   = p->l4_proto;
    nf->first_seen = nf->last_seen = now;
    pthread_mutex_init(&nf->lock, NULL);

    pthread_rwlock_wrlock(&b->rwlock);
    for (flow_t *f = b->head; f; f = f->next) {
        if (f->flow_id == p->flow_id && !f->deleting) {
            pthread_mutex_lock(&f->lock);
            pthread_rwlock_unlock(&b->rwlock);
            pool_free(nf);
            return f;
        }
    }
    nf->next = b->head; b->head = nf;
    atomic_fetch_add(&g_flow_count, 1);
    pthread_mutex_lock(&nf->lock);
    pthread_rwlock_unlock(&b->rwlock);
    return nf;
}

/* ── Helpers ── */
static double entropy_hist(const int *h, int bins, int tot)
{
    if (tot <= 0) return 0.0;
    double H = 0.0, inv = 1.0/tot;
    for (int i = 0; i < bins; i++) {
        if (!h[i]) continue;
        double p = h[i]*inv;
        H -= p*log2(p);
    }
    return H;
}

static double payload_entropy_fn(const u_char *data, int len)
{
    if (len <= 0) return 0.0;
    int hist[256] = {0};
    for (int i = 0; i < len; i++) hist[data[i]]++;
    return entropy_hist(hist, 256, len);
}

/* [B2] slot_valid-aware variance */
static double window_variance_v(const void *arr, const uint8_t *valid,
                                 int n, int is_u32, double *mean_out)
{
    double mean = 0.0, var = 0.0; int cnt = 0;
    for (int i = 0; i < n; i++) {
        if (!valid[i]) continue;
        double v = is_u32 ? ((const uint32_t*)arr)[i]
                          : ((const uint16_t*)arr)[i];
        mean += v; cnt++;
    }
    if (cnt < 2) { *mean_out = mean; return 0.0; }
    mean /= cnt;
    for (int i = 0; i < n; i++) {
        if (!valid[i]) continue;
        double v = is_u32 ? ((const uint32_t*)arr)[i]
                          : ((const uint16_t*)arr)[i];
        double d = v-mean; var += d*d;
    }
    *mean_out = mean;
    return var/cnt;
}

static double burst_regularity_score(const double *ipds, int n)
{
    if (n < 8) return 0.0;
    double mean = 0.0;
    for (int i = 0; i < n; i++) mean += ipds[i];
    mean /= n;
    if (mean < 1e-9) return 0.8;
    double var = 0.0;
    for (int i = 0; i < n; i++) { double d=ipds[i]-mean; var+=d*d; }
    double cvar = sqrt(var/n)/mean;
    if (cvar < 0.10) return 0.85;
    if (cvar < 0.25) return 0.55;
    if (cvar < 0.50) return 0.30;
    return 0.05;
}

/* [B10] IP-ID delta scorer */
static double ipid_delta_score(const uint16_t *ip_ids,
                                const uint8_t *valid, int n)
{
    uint16_t deltas[WINDOW_SIZE]; int dc = 0;
    for (int i = 1; i < n; i++) {
        if (!valid[i]||!valid[i-1]) continue;
        deltas[dc++] = (uint16_t)(ip_ids[i] - ip_ids[i-1]);
    }
    if (dc < 8) return 0.0;
    double mean = 0.0;
    for (int i = 0; i < dc; i++) mean += deltas[i];
    mean /= dc;
    double var = 0.0;
    for (int i = 0; i < dc; i++) { double d=deltas[i]-mean; var+=d*d; }
    double std = sqrt(var/dc);
    if (std < 1.0)                         return 0.55;
    if (std < 8.0 && mean < 8.0)           return 0.60;
    if (std < 3.0 && mean>0.5 && mean<5.0) return 0.10;
    return 0.05;
}

/* ── 12-channel scoring ── */
static void compute_scores(flow_t *flow, const u_char *raw,
                           int caplen, const parsed_pkt_t *p)
{
    if (flow->pkt_count < MIN_SCORE_PKTS) return;
    if (!flow->dirty) return;   /* [B8] */
    flow->dirty = 0;

    memset(flow->channel_scores, 0, sizeof flow->channel_scores);
    flow->composite_score = 0.0;

    int n = (flow->pkt_count < WINDOW_SIZE) ? (int)flow->pkt_count : WINDOW_SIZE;
    ml_features_t *ft = &flow->features;

    /* Ch 0 + Ch 10: IPD CoV + burst */
    {
        double ipds[WINDOW_SIZE]; int valid=0;
        double mean=0.0,var=0.0;
        for (int i=1;i<n;i++) {
            double d=flow->times[i]-flow->times[i-1];
            if (d>0.0) { ipds[valid++]=d; mean+=d; }
        }
        if (valid>4) {
            mean/=valid;
            for (int i=0;i<valid;i++){double d=ipds[i]-mean;var+=d*d;}
            ft->ipd_mean=mean; ft->ipd_std=sqrt(var/valid);
            ft->ipd_cvar=(mean>1e-9)?ft->ipd_std/mean:0.0;
            if      (ft->ipd_cvar<0.10) flow->channel_scores[0]=0.85;
            else if (ft->ipd_cvar<0.25) flow->channel_scores[0]=0.55;
            else if (ft->ipd_cvar<0.50) flow->channel_scores[0]=0.25;
            else                         flow->channel_scores[0]=0.05;
            ft->burst_score          = burst_regularity_score(ipds,valid);
            flow->channel_scores[10] = ft->burst_score;
        }
    }

    /* Ch 1: length variability */
    {
        double mean=0.0,var=0.0;
        for (int i=0;i<n;i++) mean+=flow->lengths[i];
        mean/=n;
        for (int i=0;i<n;i++){double d=flow->lengths[i]-mean;var+=d*d;}
        ft->len_mean=mean; ft->len_std=sqrt(var/n);
        if      (ft->len_std<2.0)  flow->channel_scores[1]=0.85;
        else if (ft->len_std<10.0) flow->channel_scores[1]=0.60;
        else if (ft->len_std<30.0) flow->channel_scores[1]=0.30;
        else                        flow->channel_scores[1]=0.05;
    }

    /* Ch 2: protocol entropy */
    {
        int ph[256]={0};
        for (int i=0;i<n;i++) ph[flow->protocols[i]]++;
        ft->proto_entropy       = entropy_hist(ph,256,n);
        flow->channel_scores[2] = (ft->proto_entropy>0.1)?0.30:0.05;
    }

    /* Ch 3: TCP flag entropy */
    {
        int fh[256]={0}; int fn=0;
        for (int i=0;i<n;i++)
            if (flow->flags[i]){fh[(uint8_t)flow->flags[i]]++;fn++;}
        ft->flag_entropy=entropy_hist(fh,256,fn);
        if      (ft->flag_entropy>1.5) flow->channel_scores[3]=0.70;
        else if (ft->flag_entropy>0.8) flow->channel_scores[3]=0.40;
        else                            flow->channel_scores[3]=0.05;
    }

    /* Ch 4-6: TCP seq/ack/window variance [B2] */
    if (flow->l4_proto == IPPROTO_TCP) {
        double dm;
        ft->seq_var    = window_variance_v(flow->seqs,     flow->slot_valid,n,1,&dm);
        ft->ack_var    = window_variance_v(flow->acks,     flow->slot_valid,n,1,&dm);
        ft->window_var = window_variance_v(flow->win_sizes,flow->slot_valid,n,0,&dm);
        flow->channel_scores[4]=(ft->seq_var    <1e6)?0.40:0.10;
        flow->channel_scores[5]=(ft->ack_var    <1e6)?0.40:0.10;
        flow->channel_scores[6]=(ft->window_var <1e4)?0.40:0.10;
    }

    /* Ch 5 override: [B10] IP-ID delta */
    {
        double ids=ipid_delta_score(flow->ip_ids,flow->slot_valid,n);
        ft->ipid_delta_var=ids;
        if (ids>flow->channel_scores[5]) flow->channel_scores[5]=ids;
    }

    /* Ch 7: TTL variance [B1] — high var = suspicious */
    {
        double mean=0.0,var=0.0;
        for (int i=0;i<n;i++) mean+=flow->ttls[i];
        mean/=n;
        for (int i=0;i<n;i++){double d=flow->ttls[i]-mean;var+=d*d;}
        ft->ttl_var=var/n;
        if      (ft->ttl_var>10.0) flow->channel_scores[7]=0.60;
        else if (ft->ttl_var>2.0)  flow->channel_scores[7]=0.30;
        else                        flow->channel_scores[7]=0.05;
    }

    /* Ch 8: payload entropy + DNS tunnel */
    {
        double pe=0.0;
        if (raw && p->payload_len>8 && p->payload_off+p->payload_len<=caplen) {
            ft->payload_entropy=payload_entropy_fn(raw+p->payload_off,p->payload_len);
            pe=(ft->payload_entropy>7.5)?0.60:
               (ft->payload_entropy>6.0)?0.30:0.05;
        }
        if (flow->dns.dns_score>pe) pe=flow->dns.dns_score;
        flow->channel_scores[8]=pe;
    }

    /* Ch 9: directional asymmetry */
    {
        uint64_t tot=flow->bytes_fwd+flow->bytes_rev;
        if (tot>0) {
            double r=(double)flow->bytes_fwd/(double)tot;
            ft->asymmetry_ratio     = fabs(r-0.5)*2.0;
            flow->channel_scores[9] = (ft->asymmetry_ratio>0.85)?0.55:
                                      (ft->asymmetry_ratio>0.60)?0.25:0.05;
        }
    }

    /* Ch 11: retransmission rate */
    {
        double rr=(flow->pkt_count>0)
            ?(double)flow->retrans_count/(double)flow->pkt_count:0.0;
        flow->channel_scores[11]=(rr>0.15)?0.50:(rr>0.05)?0.25:0.05;
    }

    /* Weighted composite */
    static const double W[NUM_CHANNELS]=
        {2.0,2.0,0.5,1.5,1.0,1.5,1.0,1.0,2.0,1.5,2.0,1.0};
    double ws=0.0,wt=0.0;
    for (int i=0;i<NUM_CHANNELS;i++){ws+=flow->channel_scores[i]*W[i];wt+=W[i];}
    flow->composite_score=ws/wt;
}

/* ── Alert emit ── */
static void emit_alert(const flow_t *flow,
                       const parsed_pkt_t *p __attribute__((unused)))
{
    char ss[INET_ADDRSTRLEN],ds[INET_ADDRSTRLEN]; struct in_addr a;
    a.s_addr=htonl(flow->src_ip); inet_ntop(AF_INET,&a,ss,sizeof ss);
    a.s_addr=htonl(flow->dst_ip); inet_ntop(AF_INET,&a,ds,sizeof ds);
    const char *proto=(flow->l4_proto==IPPROTO_TCP)?"TCP":
                      (flow->l4_proto==IPPROTO_UDP)?"UDP":"ICMP";
    atomic_fetch_add(&g_alert_count,1); /* [B12] */

    if (g_cfg.json_output) {
        printf("{\"alert\":true,\"score\":%.4f,\"flow_id\":\"%016llx\","
               "\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,"
               "\"proto\":\"%s\",\"pkts\":%llu,\"bytes_fwd\":%llu,"
               "\"bytes_rev\":%llu,\"frags\":%u,\"icmp\":%u,"
               "\"dns_score\":%.3f,\"ipid_var\":%.3f,"
               "\"ch\":[%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,"
               "%.3f,%.3f,%.3f,%.3f,%.3f,%.3f]}\n",
               flow->composite_score,
               (unsigned long long)flow->flow_id,
               ss,ds,(unsigned)flow->src_port,(unsigned)flow->dst_port,
               proto,
               (unsigned long long)flow->pkt_count,
               (unsigned long long)flow->bytes_fwd,
               (unsigned long long)flow->bytes_rev,
               flow->fragment_count,flow->icmp_count,
               flow->dns.dns_score,flow->features.ipid_delta_var,
               flow->channel_scores[0], flow->channel_scores[1],
               flow->channel_scores[2], flow->channel_scores[3],
               flow->channel_scores[4], flow->channel_scores[5],
               flow->channel_scores[6], flow->channel_scores[7],
               flow->channel_scores[8], flow->channel_scores[9],
               flow->channel_scores[10],flow->channel_scores[11]);
    } else {
        printf("\n\xF0\x9F\x9A\xA8 STEG ALERT [%.3f] %s:%u -> %s:%u"
               " | %s | pkts=%llu frags=%u icmp=%u\n",
               flow->composite_score,
               ss,(unsigned)flow->src_port,
               ds,(unsigned)flow->dst_port,
               proto,
               (unsigned long long)flow->pkt_count,
               flow->fragment_count,flow->icmp_count);
        printf("  Timing=%.2f Len=%.2f Flags=%.2f Payload=%.2f"
               " Burst=%.2f Asym=%.2f TTL=%.2f Retrans=%.2f\n",
               flow->channel_scores[0],flow->channel_scores[1],
               flow->channel_scores[3],flow->channel_scores[8],
               flow->channel_scores[10],flow->channel_scores[9],
               flow->channel_scores[7],flow->channel_scores[11]);
        if (flow->dns.dns_score>0.0)
            printf("  DNS tunnel score=%.2f qrate=%u txt/null=%u b32b64=%u\n",
                   flow->dns.dns_score,flow->dns.window_queries,
                   flow->dns.txt_null_count,flow->dns.b32b64_count);
        if (flow->features.ipid_delta_var>0.0)
            printf("  IP-ID channel score=%.2f\n",flow->features.ipid_delta_var);
        if (g_cfg.verbose)
            printf("  ipd_cvar=%.3f len_std=%.1f ttl_var=%.1f"
                   " payload_H=%.2f asym=%.2f retrans=%u\n",
                   flow->features.ipd_cvar,flow->features.len_std,
                   flow->features.ttl_var,flow->features.payload_entropy,
                   flow->features.asymmetry_ratio,flow->retrans_count);
    }
    fflush(stdout);
}

/* ── Packet processor ── */
static void process_one(const ring_pkt_t *rp)
{
    parsed_pkt_t p;
    if (parse_packet(rp->data,(int)rp->hdr.caplen,&p)<0) return;

    double ts;
    if (g_cfg.nano_ts)
        ts=(double)rp->hdr.ts.tv_sec+(double)rp->hdr.ts.tv_usec*1e-9;
    else
        ts=(double)rp->hdr.ts.tv_sec+(double)rp->hdr.ts.tv_usec*1e-6;

    flow_t *flow=flow_lookup_or_create(&p,ts);
    if (!flow) return;
    if (flow->deleting){pthread_mutex_unlock(&flow->lock);return;}

    if (p.is_fragment){
        flow->fragment_count++;
        pthread_mutex_unlock(&flow->lock); return;
    }
    if (p.l4_proto==IPPROTO_ICMP){
        flow->icmp_count++;
        flow->pkt_count++;
        flow->last_seen=ts;
        pthread_mutex_unlock(&flow->lock); return;
    }

    int idx=(int)(flow->pkt_count % WINDOW_SIZE);

    /* [F3] Retrans check before slot write */
    if (p.l4_proto==IPPROTO_TCP && p.seq!=0){
        if (seq_set_contains(&flow->seen_seqs,p.seq))
            flow->retrans_count++;
        else
            seq_set_insert(&flow->seen_seqs,p.seq);
        if (flow->pkt_count>0 && (flow->pkt_count%SEQ_SET_SIZE)==0)
            seq_set_clear(&flow->seen_seqs);
    }

    /* [B11] DNS */
    if (p.has_dns)
        compute_dns_tunnel_score(&flow->dns,ts,p.dns_qname,p.dns_qtype);

    /* Write window slot */
    flow->times[idx]      = ts;
    flow->lengths[idx]    = p.pkt_len;
    flow->protocols[idx]  = p.l4_proto;
    flow->flags[idx]      = p.tcp_flags;
    flow->ttls[idx]       = p.ttl;
    flow->seqs[idx]       = p.seq;
    flow->acks[idx]       = p.ack;
    flow->win_sizes[idx]  = p.win;
    flow->ip_ids[idx]     = p.ip_id;
    flow->slot_valid[idx] = 1;

    if (p.is_fwd) flow->bytes_fwd+=p.pkt_len;
    else          flow->bytes_rev+=p.pkt_len;

    flow->pkt_count++;
    flow->last_seen=ts;

    /* [B8] dirty flag */
    if ((flow->pkt_count % RESCORE_INTERVAL)==0) flow->dirty=1;

    compute_scores(flow,rp->data,(int)rp->hdr.caplen,&p);

    if (flow->composite_score>g_cfg.thresh &&
        flow->pkt_count>ALERT_PKT_MIN &&
        (ts-flow->last_alerted)>=g_cfg.alert_cooldown)
    {
        emit_alert(flow,&p);
        flow->last_alerted=ts;
    }
    pthread_mutex_unlock(&flow->lock);
}

/* ── Worker thread ── */
static void *worker_thread(void *arg)
{
    (void)arg;
#ifdef __linux__
    if (g_cfg.worker_core>=0){
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(g_cfg.worker_core,&cs);
        pthread_setaffinity_np(pthread_self(),sizeof cs,&cs);
    }
#endif
    while (g_running){
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME,&ts);
        ts.tv_nsec+=10000000;
        if (ts.tv_nsec>=1000000000){ts.tv_sec++;ts.tv_nsec-=1000000000;}
        sem_timedwait(&g_ring_sem,&ts);
        uint64_t h,t;
        while(1){
            h=atomic_load_explicit(&g_ring.head,memory_order_acquire);
            t=atomic_load_explicit(&g_ring.tail,memory_order_relaxed);
            if (t==h) break;
            process_one(&g_ring.slots[t&RING_MASK]);
            atomic_store_explicit(&g_ring.tail,t+1,memory_order_release);
        }
    }
    uint64_t h=atomic_load(&g_ring.head);
    uint64_t t=atomic_load(&g_ring.tail);
    while(t!=h){process_one(&g_ring.slots[t&RING_MASK]);t++;}
    return NULL;
}

/* ── Capture callback — [B6] capped sem_post ── */
void capture_callback(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *data)
{
    (void)user;
    uint64_t h=atomic_load_explicit(&g_ring.head,memory_order_relaxed);
    uint64_t t=atomic_load_explicit(&g_ring.tail,memory_order_acquire);
    if (h-t>=RING_CAPACITY){atomic_fetch_add(&g_ring.dropped,1);return;}
    ring_pkt_t *s=&g_ring.slots[h&RING_MASK];
    s->hdr=*hdr;
    uint32_t cl=hdr->caplen<SNAPLEN?hdr->caplen:(uint32_t)SNAPLEN;
    memcpy(s->data,data,cl); s->hdr.caplen=cl;
    atomic_store_explicit(&g_ring.head,h+1,memory_order_release);
    int val=0; sem_getvalue(&g_ring_sem,&val);
    if (val==0) sem_post(&g_ring_sem);
}

/* ── Cleanup thread — [B3] fixed lock ordering ── */
void *cleanup_thread(void *arg)
{
    (void)arg;
#ifdef __linux__
    if (g_cfg.cleanup_core>=0){
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(g_cfg.cleanup_core,&cs);
        pthread_setaffinity_np(pthread_self(),sizeof cs,&cs);
    }
#endif
    while (g_running){
        sleep(30);
        double now=(double)time(NULL);
        int freed=0;
        for (int i=0;i<FLOW_HASH_SIZE;i++){
            hash_bucket_t *b=&g_table[i];
            pthread_rwlock_wrlock(&b->rwlock);
            flow_t *prev=NULL,*f=b->head;
            while (f){
                int expired=(now-f->last_seen)>g_cfg.idle_timeout||
                            (now-f->first_seen)>g_cfg.max_life;
                if (expired){
                    f->deleting=1;
                    flow_t *dead=f;
                    if (prev) prev->next=f->next; else b->head=f->next;
                    f=f->next;
                    /* [B3] release bucket lock BEFORE flow mutex */
                    pthread_rwlock_unlock(&b->rwlock);
                    pthread_mutex_lock(&dead->lock);
                    pthread_mutex_unlock(&dead->lock);
                    pthread_mutex_destroy(&dead->lock);
                    pool_free(dead);
                    atomic_fetch_sub(&g_flow_count,1);
                    freed++;
                    pthread_rwlock_wrlock(&b->rwlock);
                } else {prev=f;f=f->next;}
            }
            pthread_rwlock_unlock(&b->rwlock);
        }
        if (g_cfg.verbose && freed>0)
            fprintf(stderr,"[cleanup] expired=%d active=%d dropped=%llu\n",
                freed,atomic_load(&g_flow_count),
                (unsigned long long)atomic_load(&g_ring.dropped));
    }
    return NULL;
}

/* ── Signal handlers ── */
static pcap_t *g_handle=NULL;

static void sig_handler(int sig)
{
    (void)sig; g_running=0;
    if (g_handle) pcap_breakloop(g_handle);
}

/* [B9] SIGUSR1 live stats */
static void stats_handler(int sig)
{
    (void)sig;
    fprintf(stderr,"[stats] active_flows=%d dropped=%llu alerts=%llu\n",
        atomic_load(&g_flow_count),
        (unsigned long long)atomic_load(&g_ring.dropped),
        (unsigned long long)atomic_load(&g_alert_count));
}

/* ── CLI ── */
static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <interface|pcap_file>\n\n"
        "  -t <thresh>    Alert threshold           (default: %.2f)\n"
        "  -a <sec>       Per-flow alert cooldown   (default: %.0f)\n"
        "  -i <sec>       Idle flow timeout         (default: %d)\n"
        "  -l <sec>       Max flow lifetime         (default: %d)\n"
        "  -j             JSON output\n"
        "  -p             Disable promiscuous mode\n"
        "  -n             Nanosecond timestamps\n"
        "  -W <core>      Pin worker thread to CPU core\n"
        "  -C <core>      Pin cleanup thread to CPU core\n"
        "  -v             Verbose\n"
        "  -h             Help\n\n"
        "Signals:\n"
        "  SIGUSR1        Print live stats\n",
        prog,DEFAULT_THRESH,DEFAULT_COOLDOWN,DEFAULT_IDLE,DEFAULT_MAXLIFE);
}

static int parse_args(int argc,char *argv[])
{
    int opt;
    while ((opt=getopt(argc,argv,"t:a:i:l:jpnW:C:vh"))!=-1){
        switch(opt){
        case 't': g_cfg.thresh         =atof(optarg); break;
        case 'a': g_cfg.alert_cooldown =atof(optarg); break;
        case 'i': g_cfg.idle_timeout   =atoi(optarg); break;
        case 'l': g_cfg.max_life       =atoi(optarg); break;
        case 'j': g_cfg.json_output    =1;            break;
        case 'p': g_cfg.promiscuous    =0;            break;
        case 'n': g_cfg.nano_ts        =1;            break;
        case 'W': g_cfg.worker_core    =atoi(optarg); break;
        case 'C': g_cfg.cleanup_core   =atoi(optarg); break;
        case 'v': g_cfg.verbose        =1;            break;
        case 'h': print_usage(argv[0]); return -1;
        default:  print_usage(argv[0]); return -1;
        }
    }
    if (optind>=argc){
        fprintf(stderr,"Error: no source specified.\n");
        print_usage(argv[0]); return -1;
    }
    g_cfg.source=argv[optind];
    return 0;
}

/* ── main() ── */
int main(int argc,char *argv[])
{
    if (parse_args(argc,argv)<0) return 1;

    pool_init();
    sem_init(&g_ring_sem,0,0);
    for (int i=0;i<FLOW_HASH_SIZE;i++)
        pthread_rwlock_init(&g_table[i].rwlock,NULL);

    signal(SIGINT, sig_handler);
    signal(SIGTERM,sig_handler);
    signal(SIGUSR1,stats_handler); /* [B9] */

    char errbuf[PCAP_ERRBUF_SIZE];

    /* [B5] stat() based file detection */
    struct stat st;
    int is_file=(stat(g_cfg.source,&st)==0 && S_ISREG(st.st_mode));

    if (is_file){
        g_handle=pcap_open_offline(g_cfg.source,errbuf);
    } else {
        g_handle=pcap_create(g_cfg.source,errbuf);
        if (g_handle){
            pcap_set_snaplen(g_handle,SNAPLEN);
            pcap_set_promisc(g_handle,g_cfg.promiscuous);
            pcap_set_timeout(g_handle,1);
            pcap_set_buffer_size(g_handle,KERNEL_RING_BYTES);
#ifdef PCAP_TSTAMP_PRECISION_NANO
            if (g_cfg.nano_ts)
                pcap_set_tstamp_precision(g_handle,PCAP_TSTAMP_PRECISION_NANO);
#endif
            if (pcap_activate(g_handle)!=0){
                fprintf(stderr,"pcap_activate: %s\n",pcap_geterr(g_handle));
                pcap_close(g_handle); return 1;
            }
        }
    }
    if (!g_handle){fprintf(stderr,"pcap: %s\n",errbuf);return 1;}

    /* [B7] Include ICMP */
    struct bpf_program fp;
    if (pcap_compile(g_handle,&fp,"tcp or udp or icmp",
                     0,PCAP_NETMASK_UNKNOWN)==0){
        pcap_setfilter(g_handle,&fp);
        pcap_freecode(&fp);
    }

    pthread_t wtid,ctid;
    pthread_create(&wtid,NULL,worker_thread, NULL);
    pthread_create(&ctid,NULL,cleanup_thread,NULL);

    if (!g_cfg.json_output)
        fprintf(stderr,
            "=== Oneida v4.2 ===\n"
            "Source    : %s\n"
            "Threshold : %.2f | Cooldown: %.0fs | Flows: %d | Window: %d\n"
            "Kernel buf: %d MB | Nano-ts: %s\n"
            "Send SIGUSR1 for live stats.\n\n",
            g_cfg.source,g_cfg.thresh,g_cfg.alert_cooldown,
            MAX_FLOWS,WINDOW_SIZE,
            KERNEL_RING_BYTES/(1024*1024),
            g_cfg.nano_ts?"yes":"no");

    pcap_loop(g_handle,0,capture_callback,NULL);

    g_running=0;
    sem_post(&g_ring_sem);
    pthread_join(wtid,NULL);
    pthread_join(ctid,NULL);
    pcap_close(g_handle);
    sem_destroy(&g_ring_sem);

    if (!g_cfg.json_output)
        fprintf(stderr,"\nDone. active=%d dropped=%llu alerts=%llu\n",
            atomic_load(&g_flow_count),
            (unsigned long long)atomic_load(&g_ring.dropped),
            (unsigned long long)atomic_load(&g_alert_count));
    return 0;
}
