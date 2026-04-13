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
#include <unistd.h>
#include <getopt.h>
#include <sched.h>
#include <sys/mman.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* ============================================================
 * Oneida v4.0 — Full Refactor
 * 12-Channel Network Steganography Detector
 * ============================================================
 * Changes vs v3.1:
 *  - Per-bucket read-write locks (vs single global mutex)
 *  - Lock-free ring buffer for capture->worker pipeline
 *  - Canonical bidirectional flow ID (A->B == B->A)
 *  - RCU-style safe flow expiry (no UAF)
 *  - Improved 12-channel scoring (CoV, burst, asymmetry)
 *  - Payload entropy via captured bytes
 *  - JSON + plain-text alert output modes
 *  - IPv6 stubs (graceful skip)
 *  - Configurable via CLI flags
 *  - Graceful shutdown with SIGINT/SIGTERM
 * ============================================================ */

#ifndef MAX_FLOWS
#  define MAX_FLOWS          32768
#endif
#ifndef FLOW_HASH_SIZE
#  define FLOW_HASH_SIZE     8192
#endif
#ifndef WINDOW_SIZE
#  define WINDOW_SIZE        256
#endif
#define NUM_CHANNELS         12
#define RING_CAPACITY        65536
#define RING_MASK            (RING_CAPACITY - 1)
#define DEFAULT_THRESH       0.45
#define DEFAULT_IDLE_TIMEOUT 300
#define DEFAULT_MAX_LIFE     3600
#define SNAPLEN              9216
#define MIN_SCORE_PKTS       20
#define ALERT_PKT_MIN        30
#define L2_LEN               14

typedef struct {
    const char *source;
    double      thresh;
    int         idle_timeout;
    int         max_life;
    int         json_output;
    int         promiscuous;
    int         worker_core;
    int         cleanup_core;
    int         verbose;
} config_t;

static config_t g_cfg = {
    .thresh        = DEFAULT_THRESH,
    .idle_timeout  = DEFAULT_IDLE_TIMEOUT,
    .max_life      = DEFAULT_MAX_LIFE,
    .json_output   = 0,
    .promiscuous   = 1,
    .worker_core   = -1,
    .cleanup_core  = -1,
    .verbose       = 0,
};

typedef struct {
    double ipd_mean, ipd_std, ipd_cvar;
    double len_mean, len_std;
    double proto_entropy, flag_entropy;
    double seq_var, ack_var, window_var;
    double ttl_var;
    double ipid_pred;
    double payload_entropy;
    double burst_score;
    double asymmetry_ratio;
    int    retrans_count;
} ml_features_t;

typedef struct flow_t flow_t;

struct flow_t {
    uint64_t flow_id;
    uint32_t src_ip,  dst_ip;
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

    uint64_t bytes_fwd, bytes_rev;
    uint64_t pkt_count;
    uint32_t retrans_count;

    double        channel_scores[NUM_CHANNELS];
    double        composite_score;
    ml_features_t features;

    double first_seen, last_seen;
    volatile int    deleting;
    pthread_mutex_t lock;
    flow_t *next;
};

typedef struct {
    flow_t          *head;
    pthread_rwlock_t rwlock;
} hash_bucket_t;

static hash_bucket_t g_table[FLOW_HASH_SIZE];
static atomic_int    g_flow_count = 0;
static volatile int  g_running    = 1;

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
                                    uint16_t sp,  uint16_t dp,
                                    uint8_t proto)
{
    uint32_t lo_ip, hi_ip; uint16_t lo_pt, hi_pt;
    if (sip < dip || (sip == dip && sp <= dp)) {
        lo_ip = sip; hi_ip = dip; lo_pt = sp; hi_pt = dp;
    } else {
        lo_ip = dip; hi_ip = sip; lo_pt = dp; hi_pt = sp;
    }
    uint64_t id = (uint64_t)lo_ip | ((uint64_t)hi_ip << 32);
    id ^= ((uint64_t)lo_pt << 48);
    id ^= ((uint64_t)hi_pt << 56);
    id ^= ((uint64_t)proto << 40);
    return mix64(id);
}

typedef struct {
    uint64_t flow_id;
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port, pkt_len, win;
    uint8_t  l4_proto, ttl, tcp_flags;
    uint32_t seq, ack;
    int      payload_off, payload_len, is_fwd;
} parsed_pkt_t;

static int parse_packet(const u_char *pkt, int caplen, parsed_pkt_t *out)
{
    if (caplen < L2_LEN + 20) return -1;
    const u_char *ip_ptr = pkt + L2_LEN;
    if (((ip_ptr[0] >> 4) & 0x0F) != 4) return -1;
    uint8_t ip_hlen = (ip_ptr[0] & 0x0F) * 4;
    if (ip_hlen < 20 || caplen < L2_LEN + ip_hlen) return -1;

    out->l4_proto = ip_ptr[9];
    out->pkt_len  = (uint16_t)((ip_ptr[2] << 8) | ip_ptr[3]);
    out->ttl      = ip_ptr[8];
    memcpy(&out->src_ip, ip_ptr + 12, 4); out->src_ip = ntohl(out->src_ip);
    memcpy(&out->dst_ip, ip_ptr + 16, 4); out->dst_ip = ntohl(out->dst_ip);

    const u_char *l4 = ip_ptr + ip_hlen;
    int l4_avail = caplen - L2_LEN - ip_hlen;
    out->tcp_flags = 0; out->seq = out->ack = out->win = 0;
    out->src_port  = out->dst_port = 0;

    if (out->l4_proto == IPPROTO_TCP) {
        if (l4_avail < 20) return -1;
        uint8_t thl = ((l4[12] >> 4) & 0x0F) * 4;
        if (thl < 20 || l4_avail < thl) return -1;
        out->src_port  = (uint16_t)((l4[0]<<8)|l4[1]);
        out->dst_port  = (uint16_t)((l4[2]<<8)|l4[3]);
        out->seq       = (uint32_t)((l4[4]<<24)|(l4[5]<<16)|(l4[6]<<8)|l4[7]);
        out->ack       = (uint32_t)((l4[8]<<24)|(l4[9]<<16)|(l4[10]<<8)|l4[11]);
        out->tcp_flags = l4[13];
        out->win       = (uint16_t)((l4[14]<<8)|l4[15]);
        out->payload_off = (int)(l4 - pkt) + thl;
        out->payload_len = l4_avail - thl;
    } else if (out->l4_proto == IPPROTO_UDP) {
        if (l4_avail < 8) return -1;
        out->src_port    = (uint16_t)((l4[0]<<8)|l4[1]);
        out->dst_port    = (uint16_t)((l4[2]<<8)|l4[3]);
        out->payload_off = (int)(l4 - pkt) + 8;
        out->payload_len = l4_avail - 8;
    } else return -1;

    if (out->payload_len < 0) out->payload_len = 0;
    out->flow_id = make_flow_id(out->src_ip, out->dst_ip,
                                out->src_port, out->dst_port, out->l4_proto);
    uint32_t lo = (out->src_ip < out->dst_ip ||
                  (out->src_ip == out->dst_ip && out->src_port <= out->dst_port))
                  ? out->src_ip : out->dst_ip;
    out->is_fwd = (out->src_ip == lo) ? 1 : 0;
    return 0;
}

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
    flow_t *nf = calloc(1, sizeof(flow_t));
    if (!nf) return NULL;
    nf->flow_id = p->flow_id; nf->src_ip = p->src_ip; nf->dst_ip = p->dst_ip;
    nf->src_port = p->src_port; nf->dst_port = p->dst_port;
    nf->l4_proto = p->l4_proto;
    nf->first_seen = nf->last_seen = now;
    pthread_mutex_init(&nf->lock, NULL);

    pthread_rwlock_wrlock(&b->rwlock);
    for (flow_t *f = b->head; f; f = f->next) {
        if (f->flow_id == p->flow_id && !f->deleting) {
            pthread_mutex_lock(&f->lock);
            pthread_rwlock_unlock(&b->rwlock);
            free(nf); return f;
        }
    }
    nf->next = b->head; b->head = nf;
    atomic_fetch_add(&g_flow_count, 1);
    pthread_mutex_lock(&nf->lock);
    pthread_rwlock_unlock(&b->rwlock);
    return nf;
}

static double entropy_hist(const int *hist, int bins, int total)
{
    if (total <= 0) return 0.0;
    double H = 0.0, inv = 1.0 / total;
    for (int i = 0; i < bins; i++) {
        if (!hist[i]) continue;
        double p = hist[i] * inv; H -= p * log2(p);
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

static double window_variance(const void *arr, int n,
                              int elem_size __attribute__((unused)),
                              int is_u32, double *mean_out)
{
    double mean = 0.0, var = 0.0; int cnt = 0;
    for (int i = 0; i < n; i++) {
        double v = is_u32 ? ((const uint32_t *)arr)[i]
                          : ((const uint16_t *)arr)[i];
        if (v == 0) continue; mean += v; cnt++;
    }
    if (cnt < 2) { *mean_out = mean; return 0.0; }
    mean /= cnt;
    for (int i = 0; i < n; i++) {
        double v = is_u32 ? ((const uint32_t *)arr)[i]
                          : ((const uint16_t *)arr)[i];
        if (v == 0) continue; double d = v - mean; var += d * d;
    }
    *mean_out = mean; return var / cnt;
}

static double burst_regularity_score(const double *ipds, int n)
{
    if (n < 8) return 0.0;
    double mean = 0.0;
    for (int i = 0; i < n; i++) mean += ipds[i];
    mean /= n;
    if (mean < 1e-9) return 0.8;
    double var = 0.0;
    for (int i = 0; i < n; i++) { double d = ipds[i]-mean; var += d*d; }
    double cvar = sqrt(var / n) / mean;
    if (cvar < 0.10) return 0.85;
    if (cvar < 0.25) return 0.55;
    if (cvar < 0.50) return 0.30;
    return 0.05;
}

static void compute_scores(flow_t *flow, const u_char *raw_pkt,
                           int caplen, const parsed_pkt_t *p)
{
    if (flow->pkt_count < MIN_SCORE_PKTS) return;
    int n = (flow->pkt_count < WINDOW_SIZE) ? (int)flow->pkt_count : WINDOW_SIZE;
    ml_features_t *ft = &flow->features;

    /* Ch 0 + Ch 10: IPD CoV and burst regularity */
    {
        double ipds[WINDOW_SIZE]; int valid = 0;
        double mean = 0.0, var = 0.0;
        for (int i = 1; i < n; i++) {
            double d = flow->times[i] - flow->times[i-1];
            if (d > 0.0) { ipds[valid++] = d; mean += d; }
        }
        if (valid > 4) {
            mean /= valid;
            for (int i=0; i<valid; i++) { double d=ipds[i]-mean; var+=d*d; }
            ft->ipd_mean = mean; ft->ipd_std = sqrt(var/valid);
            ft->ipd_cvar = (mean > 1e-9) ? ft->ipd_std/mean : 0.0;
            if      (ft->ipd_cvar < 0.10) flow->channel_scores[0] = 0.85;
            else if (ft->ipd_cvar < 0.25) flow->channel_scores[0] = 0.55;
            else if (ft->ipd_cvar < 0.50) flow->channel_scores[0] = 0.25;
            else                           flow->channel_scores[0] = 0.05;
            ft->burst_score = burst_regularity_score(ipds, valid);
            flow->channel_scores[10] = ft->burst_score;
        }
    }

    /* Ch 1: length variability */
    {
        double mean = 0.0, var = 0.0;
        for (int i=0; i<n; i++) mean += flow->lengths[i];
        mean /= n;
        for (int i=0; i<n; i++) { double d=flow->lengths[i]-mean; var+=d*d; }
        ft->len_mean = mean; ft->len_std = sqrt(var/n);
        if      (ft->len_std < 2.0)  flow->channel_scores[1] = 0.85;
        else if (ft->len_std < 10.0) flow->channel_scores[1] = 0.60;
        else if (ft->len_std < 30.0) flow->channel_scores[1] = 0.30;
        else                          flow->channel_scores[1] = 0.05;
    }

    /* Ch 2: protocol entropy */
    {
        int ph[256] = {0};
        for (int i=0; i<n; i++) ph[flow->protocols[i]]++;
        ft->proto_entropy = entropy_hist(ph, 256, n);
        flow->channel_scores[2] = (ft->proto_entropy > 0.1) ? 0.30 : 0.05;
    }

    /* Ch 3: TCP flag entropy */
    {
        int fh[256]={0}; int fn=0;
        for (int i=0; i<n; i++)
            if (flow->flags[i]) { fh[(uint8_t)flow->flags[i]]++; fn++; }
        ft->flag_entropy = entropy_hist(fh, 256, fn);
        flow->channel_scores[3] = (ft->flag_entropy < 0.5 && fn > 0) ? 0.50 : 0.10;
    }

    /* Ch 4-6: TCP seq/ack/win variance */
    if (flow->l4_proto == IPPROTO_TCP) {
        double dummy;
        ft->seq_var    = window_variance(flow->seqs,      n, 4, 1, &dummy);
        ft->ack_var    = window_variance(flow->acks,      n, 4, 1, &dummy);
        ft->window_var = window_variance(flow->win_sizes, n, 2, 0, &dummy);
        int sn=0,an=0,wn=0;
        for (int i=0;i<n;i++) {
            if(flow->seqs[i]) sn++; if(flow->acks[i]) an++;
            if(flow->win_sizes[i]) wn++;
        }
        flow->channel_scores[4]=(ft->seq_var    <1e6&&sn>10)?0.40:0.10;
        flow->channel_scores[5]=(ft->ack_var    <1e6&&an>10)?0.40:0.10;
        flow->channel_scores[6]=(ft->window_var <1e4&&wn>10)?0.40:0.10;
    }

    /* Ch 7: TTL variance */
    {
        double mean=0.0,var=0.0;
        for(int i=0;i<n;i++) mean+=flow->ttls[i]; mean/=n;
        for(int i=0;i<n;i++){double d=flow->ttls[i]-mean;var+=d*d;}
        ft->ttl_var=var/n;
        flow->channel_scores[7]=(ft->ttl_var<5.0)?0.40:0.10;
    }

    /* Ch 8: payload entropy */
    if (raw_pkt && p->payload_len > 8 &&
        p->payload_off + p->payload_len <= caplen) {
        ft->payload_entropy = payload_entropy_fn(raw_pkt+p->payload_off, p->payload_len);
        flow->channel_scores[8] = (ft->payload_entropy>7.5)?0.60:
                                  (ft->payload_entropy>6.0)?0.30:0.05;
    }

    /* Ch 9: directional asymmetry */
    {
        uint64_t tot = flow->bytes_fwd + flow->bytes_rev;
        if (tot > 0) {
            double r = (double)flow->bytes_fwd / (double)tot;
            ft->asymmetry_ratio = fabs(r - 0.5) * 2.0;
            flow->channel_scores[9] = (ft->asymmetry_ratio>0.85)?0.55:
                                      (ft->asymmetry_ratio>0.60)?0.25:0.05;
        }
    }

    /* Ch 11: retransmission rate */
    {
        double rr = (flow->pkt_count>0)
            ? (double)flow->retrans_count/(double)flow->pkt_count : 0.0;
        flow->channel_scores[11]=(rr>0.15)?0.50:(rr>0.05)?0.25:0.05;
    }

    /* Weighted composite */
    static const double W[NUM_CHANNELS]={2.0,2.0,0.5,1.5,1.0,1.0,1.0,1.0,2.0,1.5,2.0,1.0};
    double ws=0.0, wt=0.0;
    for (int i=0;i<NUM_CHANNELS;i++){ws+=flow->channel_scores[i]*W[i];wt+=W[i];}
    flow->composite_score = ws/wt;
}

static void emit_alert(const flow_t *flow,
                       const parsed_pkt_t *p __attribute__((unused)))
{
    char ss[INET_ADDRSTRLEN], ds[INET_ADDRSTRLEN]; struct in_addr a;
    a.s_addr=htonl(flow->src_ip); inet_ntop(AF_INET,&a,ss,sizeof ss);
    a.s_addr=htonl(flow->dst_ip); inet_ntop(AF_INET,&a,ds,sizeof ds);
    const char *proto = (flow->l4_proto==IPPROTO_TCP)?"TCP":"UDP";

    if (g_cfg.json_output) {
        printf("{\"alert\":true,\"score\":%.4f,\"flow_id\":\"%016llx\","
               "\"src\":\"%s\",\"dst\":\"%s\",\"sport\":%u,\"dport\":%u,"
               "\"proto\":\"%s\",\"pkts\":%llu,\"bytes_fwd\":%llu,\"bytes_rev\":%llu,"
               "\"ch\":[%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f]}\n",
               flow->composite_score,(unsigned long long)flow->flow_id,
               ss,ds,(unsigned)flow->src_port,(unsigned)flow->dst_port,proto,
               (unsigned long long)flow->pkt_count,
               (unsigned long long)flow->bytes_fwd,(unsigned long long)flow->bytes_rev,
               flow->channel_scores[0], flow->channel_scores[1],
               flow->channel_scores[2], flow->channel_scores[3],
               flow->channel_scores[4], flow->channel_scores[5],
               flow->channel_scores[6], flow->channel_scores[7],
               flow->channel_scores[8], flow->channel_scores[9],
               flow->channel_scores[10],flow->channel_scores[11]);
    } else {
        printf("\n\xF0\x9F\x9A\xA8 STEG ALERT [%.3f] %s:%u -> %s:%u | %s | pkts=%llu\n",
               flow->composite_score,ss,(unsigned)flow->src_port,
               ds,(unsigned)flow->dst_port,proto,(unsigned long long)flow->pkt_count);
        printf("  Timing=%.2f Len=%.2f Flags=%.2f Payload=%.2f"
               " Burst=%.2f Asym=%.2f TTL=%.2f Retrans=%.2f\n",
               flow->channel_scores[0],flow->channel_scores[1],
               flow->channel_scores[3],flow->channel_scores[8],
               flow->channel_scores[10],flow->channel_scores[9],
               flow->channel_scores[7],flow->channel_scores[11]);
        if (g_cfg.verbose)
            printf("  ipd_cvar=%.3f len_std=%.1f ttl_var=%.1f"
                   " payload_H=%.2f asym=%.2f\n",
                   flow->features.ipd_cvar,flow->features.len_std,
                   flow->features.ttl_var,flow->features.payload_entropy,
                   flow->features.asymmetry_ratio);
    }
    fflush(stdout);
}

static void process_one(const ring_pkt_t *rp)
{
    parsed_pkt_t p;
    if (parse_packet(rp->data,(int)rp->hdr.caplen,&p)<0) return;
    double ts = (double)rp->hdr.ts.tv_sec + rp->hdr.ts.tv_usec*1e-6;
    flow_t *flow = flow_lookup_or_create(&p, ts);
    if (!flow) return;
    if (flow->deleting) { pthread_mutex_unlock(&flow->lock); return; }

    int idx = (int)(flow->pkt_count % WINDOW_SIZE);
    flow->times[idx]=ts; flow->lengths[idx]=p.pkt_len;
    flow->protocols[idx]=p.l4_proto; flow->flags[idx]=p.tcp_flags;
    flow->ttls[idx]=p.ttl; flow->seqs[idx]=p.seq;
    flow->acks[idx]=p.ack; flow->win_sizes[idx]=p.win;

    if (p.l4_proto==IPPROTO_TCP && p.seq!=0 && flow->pkt_count>0) {
        int w=(int)((flow->pkt_count<WINDOW_SIZE)?flow->pkt_count:WINDOW_SIZE);
        for(int k=0;k<w;k++) {
            if(k==idx) continue;
            if(flow->seqs[k]==p.seq){flow->retrans_count++;break;}
        }
    }

    if (p.is_fwd) flow->bytes_fwd+=p.pkt_len; else flow->bytes_rev+=p.pkt_len;
    flow->pkt_count++; flow->last_seen=ts;
    compute_scores(flow,rp->data,(int)rp->hdr.caplen,&p);
    if (flow->composite_score>g_cfg.thresh && flow->pkt_count>ALERT_PKT_MIN)
        emit_alert(flow,&p);
    pthread_mutex_unlock(&flow->lock);
}

static void *worker_thread(void *arg)
{
    (void)arg;
#ifdef __linux__
    if (g_cfg.worker_core>=0) {
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(g_cfg.worker_core,&cs);
        pthread_setaffinity_np(pthread_self(),sizeof cs,&cs);
    }
#endif
    while (g_running) {
        uint64_t h=atomic_load_explicit(&g_ring.head,memory_order_acquire);
        uint64_t t=atomic_load_explicit(&g_ring.tail,memory_order_relaxed);
        if (t==h){usleep(10);continue;}
        process_one(&g_ring.slots[t&RING_MASK]);
        atomic_store_explicit(&g_ring.tail,t+1,memory_order_release);
    }
    uint64_t h=atomic_load(&g_ring.head), t=atomic_load(&g_ring.tail);
    while(t!=h){process_one(&g_ring.slots[t&RING_MASK]);t++;}
    return NULL;
}

void capture_callback(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *data)
{
    (void)user;
    uint64_t h=atomic_load_explicit(&g_ring.head,memory_order_relaxed);
    uint64_t t=atomic_load_explicit(&g_ring.tail,memory_order_acquire);
    if (h-t>=RING_CAPACITY){atomic_fetch_add(&g_ring.dropped,1);return;}
    ring_pkt_t *s=&g_ring.slots[h&RING_MASK];
    s->hdr=*hdr;
    uint32_t cl=hdr->caplen<SNAPLEN?hdr->caplen:SNAPLEN;
    memcpy(s->data,data,cl); s->hdr.caplen=cl;
    atomic_store_explicit(&g_ring.head,h+1,memory_order_release);
}

void *cleanup_thread(void *arg)
{
    (void)arg;
#ifdef __linux__
    if (g_cfg.cleanup_core>=0) {
        cpu_set_t cs; CPU_ZERO(&cs); CPU_SET(g_cfg.cleanup_core,&cs);
        pthread_setaffinity_np(pthread_self(),sizeof cs,&cs);
    }
#endif
    while (g_running) {
        sleep(30);
        double now=(double)time(NULL); int freed=0;
        for (int i=0;i<FLOW_HASH_SIZE;i++) {
            hash_bucket_t *b=&g_table[i];
            pthread_rwlock_wrlock(&b->rwlock);
            flow_t *prev=NULL,*f=b->head;
            while(f){
                int exp=(now-f->last_seen)>g_cfg.idle_timeout ||
                        (now-f->first_seen)>g_cfg.max_life;
                if(exp){
                    f->deleting=1;
                    flow_t *dead=f;
                    if(prev) prev->next=f->next; else b->head=f->next;
                    f=f->next;
                    pthread_mutex_lock(&dead->lock);
                    pthread_mutex_unlock(&dead->lock);
                    pthread_mutex_destroy(&dead->lock);
                    free(dead);
                    atomic_fetch_sub(&g_flow_count,1);
                    freed++;
                } else { prev=f; f=f->next; }
            }
            pthread_rwlock_unlock(&b->rwlock);
        }
        if(g_cfg.verbose && freed>0)
            fprintf(stderr,"[cleanup] expired %d | active=%d | dropped=%llu\n",
                freed,atomic_load(&g_flow_count),
                (unsigned long long)atomic_load(&g_ring.dropped));
    }
    return NULL;
}

static pcap_t *g_handle=NULL;
static void sig_handler(int sig){(void)sig;g_running=0;if(g_handle)pcap_breakloop(g_handle);}

static void print_usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [options] <interface|pcap_file>\n\n"
        "  -t <thresh>    Alert threshold       (default: %.2f)\n"
        "  -i <sec>       Idle flow timeout     (default: %d)\n"
        "  -l <sec>       Max flow lifetime     (default: %d)\n"
        "  -j             JSON output\n"
        "  -p             Disable promiscuous mode\n"
        "  -W <core>      Pin worker to CPU core\n"
        "  -C <core>      Pin cleanup to CPU core\n"
        "  -v             Verbose\n"
        "  -h             Help\n",
        prog,DEFAULT_THRESH,DEFAULT_IDLE_TIMEOUT,DEFAULT_MAX_LIFE);
}

static int parse_args(int argc, char *argv[])
{
    int opt;
    while((opt=getopt(argc,argv,"t:i:l:jpW:C:vh"))!=-1){
        switch(opt){
        case 't': g_cfg.thresh=atof(optarg);       break;
        case 'i': g_cfg.idle_timeout=atoi(optarg); break;
        case 'l': g_cfg.max_life=atoi(optarg);     break;
        case 'j': g_cfg.json_output=1;             break;
        case 'p': g_cfg.promiscuous=0;             break;
        case 'W': g_cfg.worker_core=atoi(optarg);  break;
        case 'C': g_cfg.cleanup_core=atoi(optarg); break;
        case 'v': g_cfg.verbose=1;                 break;
        case 'h': print_usage(argv[0]); return -1;
        default:  print_usage(argv[0]); return -1;
        }
    }
    if(optind>=argc){
        fprintf(stderr,"Error: no source specified.\n");
        print_usage(argv[0]); return -1;
    }
    g_cfg.source=argv[optind];
    return 0;
}

int main(int argc, char *argv[])
{
    if(parse_args(argc,argv)<0) return 1;

    for(int i=0;i<FLOW_HASH_SIZE;i++)
        pthread_rwlock_init(&g_table[i].rwlock,NULL);

    signal(SIGINT,sig_handler); signal(SIGTERM,sig_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    int is_file=(strstr(g_cfg.source,".pcap")!=NULL||
                 strstr(g_cfg.source,".pcapng")!=NULL);

    g_handle=is_file
        ? pcap_open_offline(g_cfg.source,errbuf)
        : pcap_open_live(g_cfg.source,SNAPLEN,g_cfg.promiscuous,1,errbuf);

    if(!g_handle){fprintf(stderr,"pcap: %s\n",errbuf);return 1;}

    struct bpf_program fp;
    if(pcap_compile(g_handle,&fp,"tcp or udp",0,PCAP_NETMASK_UNKNOWN)==0){
        pcap_setfilter(g_handle,&fp); pcap_freecode(&fp);
    }

    pthread_t wtid,ctid;
    pthread_create(&wtid,NULL,worker_thread,NULL);
    pthread_create(&ctid,NULL,cleanup_thread,NULL);

    if(!g_cfg.json_output)
        fprintf(stderr,"=== Oneida v4.0 | src=%s | thresh=%.2f | flows=%d ===\n\n",
                g_cfg.source,g_cfg.thresh,MAX_FLOWS);

    pcap_loop(g_handle,0,capture_callback,NULL);

    g_running=0;
    pthread_join(wtid,NULL); pthread_join(ctid,NULL);
    pcap_close(g_handle);

    if(!g_cfg.json_output)
        fprintf(stderr,"\nDone. active=%d dropped=%llu\n",
                atomic_load(&g_flow_count),
                (unsigned long long)atomic_load(&g_ring.dropped));
    return 0;
}
