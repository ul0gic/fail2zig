// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026 fail2zig maintainers

// Independent nftables inventory over raw NETLINK_NETFILTER, written from the kernel uapi
// headers only (no product code, no libnftnl). Prints the selected tables' chains and sets,
// their elements sorted by address, and rules in kernel chain order with decoded address
// matches. Anonymous sets are not counted. Element deadlines are dump start plus remaining
// expiration; each set line prints its dump latency, the bound on that bias. A listing is
// accepted only when the ruleset generation is unchanged across it.
// Build: gcc -O2 -Wall -Wextra -o kernel_oracle tests/harness/load_repro/kernel_oracle.c
// Usage: kernel_oracle [--prefix NAME_PREFIX | --table NAME]   (default prefix "f2z_")
// Exit: 0 listing complete (possibly no table), 1 netlink/system error, 2 truncated,
//       malformed or unexpected message, 3 usage, 4 ruleset generation changed during dump.
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#define RX_SIZE (1u << 20)
#define MAX_TABLES 16
#define MAX_SETS 64
#define MAX_ELEMS 200000
#define NAME_LEN 256

enum { EXIT_NL = 1, EXIT_MALFORMED = 2, EXIT_USAGE = 3, EXIT_CHANGED = 4 };

static int fd = -1;
static uint32_t seq_counter = 1;
static unsigned char *rx;

static long long wall_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void die(int code, const char *what) {
    fprintf(stderr, "kernel_oracle: %s\n", what);
    exit(code);
}

typedef struct { const struct nlattr *a[64]; } Attrs;

// Rejects attributes that overrun their container; the kernel never emits them.
static void parse_attrs(Attrs *out, const void *data, size_t len) {
    memset(out, 0, sizeof(*out));
    const unsigned char *p = data;
    while (len > 0) {
        if (len < NLA_HDRLEN) die(EXIT_MALFORMED, "truncated attribute header");
        const struct nlattr *nla = (const struct nlattr *)p;
        if (nla->nla_len < NLA_HDRLEN || nla->nla_len > len) die(EXIT_MALFORMED, "attribute length out of bounds");
        unsigned type = nla->nla_type & NLA_TYPE_MASK;
        if (type < 64) out->a[type] = nla;
        size_t step = NLA_ALIGN(nla->nla_len);
        if (step > len) step = len;
        p += step;
        len -= step;
    }
}

static const void *attr_data(const struct nlattr *a) { return (const unsigned char *)a + NLA_HDRLEN; }
static size_t attr_len(const struct nlattr *a) { return a->nla_len - NLA_HDRLEN; }

static uint32_t attr_u32(const struct nlattr *a) {
    if (!a || attr_len(a) != 4) die(EXIT_MALFORMED, "bad u32 attribute");
    uint32_t v;
    memcpy(&v, attr_data(a), 4);
    return ntohl(v);
}

static uint64_t attr_u64(const struct nlattr *a) {
    if (!a || attr_len(a) != 8) die(EXIT_MALFORMED, "bad u64 attribute");
    const unsigned char *b = attr_data(a);
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | b[i];
    return v;
}

static void attr_str(const struct nlattr *a, char *out, size_t cap) {
    if (!a) die(EXIT_MALFORMED, "missing string attribute");
    size_t n = attr_len(a);
    const char *s = attr_data(a);
    if (n == 0 || n > cap || s[n - 1] != '\0' || strlen(s) != n - 1) die(EXIT_MALFORMED, "bad string attribute");
    memcpy(out, s, n);
}

// nft_data VALUE inside a nested attribute; returns its length.
static size_t nested_value(const struct nlattr *a, unsigned char *out, size_t cap) {
    if (!a) die(EXIT_MALFORMED, "missing data attribute");
    Attrs d;
    parse_attrs(&d, attr_data(a), attr_len(a));
    if (!d.a[NFTA_DATA_VALUE]) die(EXIT_MALFORMED, "data attribute without value");
    size_t n = attr_len(d.a[NFTA_DATA_VALUE]);
    if (n > cap) die(EXIT_MALFORMED, "data value too long");
    memcpy(out, attr_data(d.a[NFTA_DATA_VALUE]), n);
    return n;
}

typedef void (*MsgFn)(const struct nlmsghdr *nlh, const void *payload, size_t len, void *ctx);

static void request(uint16_t msg, uint16_t flags, uint8_t family, const void *attrs, size_t attrs_len, uint16_t expect, MsgFn fn, void *ctx) {
    unsigned char tx[1024] __attribute__((aligned(4)));
    size_t total = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg)) + attrs_len;
    if (total > sizeof(tx)) die(EXIT_USAGE, "request too large");
    memset(tx, 0, sizeof(tx));
    struct nlmsghdr *nlh = (struct nlmsghdr *)tx;
    nlh->nlmsg_len = (uint32_t)total;
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | msg;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = seq_counter++;
    struct nfgenmsg *ng = (struct nfgenmsg *)(tx + NLMSG_HDRLEN);
    ng->nfgen_family = family;
    ng->version = NFNETLINK_V0;
    ng->res_id = 0;
    memcpy(tx + NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg)), attrs, attrs_len);
    struct sockaddr_nl kernel = { .nl_family = AF_NETLINK };
    if (sendto(fd, tx, total, 0, (struct sockaddr *)&kernel, sizeof(kernel)) != (ssize_t)total) die(EXIT_NL, "sendto failed");

    int dump = (flags & NLM_F_DUMP) != 0;
    for (int rounds = 0; rounds < 1000000; rounds++) {
        struct iovec iov = { rx, RX_SIZE };
        struct sockaddr_nl from;
        struct msghdr mh = { .msg_name = &from, .msg_namelen = sizeof(from), .msg_iov = &iov, .msg_iovlen = 1 };
        ssize_t got = recvmsg(fd, &mh, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) die(EXIT_NL, "receive buffer overrun (ENOBUFS)");
            die(EXIT_NL, "recvmsg failed");
        }
        if (mh.msg_flags & MSG_TRUNC) die(EXIT_MALFORMED, "datagram truncated");
        if (from.nl_pid != 0) die(EXIT_MALFORMED, "message not from kernel");
        size_t left = (size_t)got;
        const unsigned char *p = rx;
        while (left > 0) {
            if (left < NLMSG_HDRLEN) die(EXIT_MALFORMED, "truncated netlink header");
            const struct nlmsghdr *h = (const struct nlmsghdr *)p;
            if (h->nlmsg_len < NLMSG_HDRLEN || h->nlmsg_len > left) die(EXIT_MALFORMED, "netlink length out of bounds");
            if (h->nlmsg_seq != nlh->nlmsg_seq) die(EXIT_MALFORMED, "unexpected sequence number");
            if (h->nlmsg_flags & NLM_F_DUMP_INTR) die(EXIT_CHANGED, "dump interrupted by concurrent change");
            if (h->nlmsg_type == NLMSG_ERROR) {
                if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(struct nlmsgerr)) die(EXIT_MALFORMED, "truncated error message");
                const struct nlmsgerr *e = (const struct nlmsgerr *)NLMSG_DATA(h);
                if (e->error == 0 && !dump) return;
                errno = -e->error;
                fprintf(stderr, "kernel_oracle: request %u failed: %s\n", msg, strerror(errno));
                exit(EXIT_NL);
            }
            if (h->nlmsg_type == NLMSG_DONE) {
                if (!dump) die(EXIT_MALFORMED, "DONE for a non-dump request");
                // A dump that failed part-way ends with a negative errno in DONE instead of
                // NLMSG_ERROR; accepting it would print a silently partial listing.
                if (h->nlmsg_len < NLMSG_HDRLEN + sizeof(int)) die(EXIT_MALFORMED, "truncated DONE message");
                int status;
                memcpy(&status, NLMSG_DATA(h), sizeof(status));
                if (status < 0) {
                    fprintf(stderr, "kernel_oracle: dump %u ended with error: %s\n", msg, strerror(-status));
                    exit(EXIT_NL);
                }
                return;
            }
            if (h->nlmsg_type != ((NFNL_SUBSYS_NFTABLES << 8) | expect)) die(EXIT_MALFORMED, "unknown message type");
            size_t hdr = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(struct nfgenmsg));
            if (h->nlmsg_len < hdr) die(EXIT_MALFORMED, "truncated nfgenmsg");
            fn(h, p + hdr, h->nlmsg_len - hdr, ctx);
            if (!dump) return;
            size_t step = NLMSG_ALIGN(h->nlmsg_len);
            if (step > left) step = left;
            p += step;
            left -= step;
        }
    }
    die(EXIT_MALFORMED, "dump did not terminate");
}

static size_t put_str_attr(unsigned char *buf, size_t off, uint16_t type, const char *s) {
    size_t n = strlen(s) + 1;
    struct nlattr *a = (struct nlattr *)(buf + off);
    a->nla_len = (uint16_t)(NLA_HDRLEN + n);
    a->nla_type = type;
    memcpy(buf + off + NLA_HDRLEN, s, n);
    return off + NLA_ALIGN(a->nla_len);
}

// ---- generation ----
static void on_gen(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    (void)h;
    Attrs a;
    parse_attrs(&a, p, n);
    *(uint32_t *)ctx = attr_u32(a.a[NFTA_GEN_ID]);
}

static uint32_t generation(void) {
    uint32_t id = 0;
    request(NFT_MSG_GETGEN, 0, NFPROTO_UNSPEC, NULL, 0, NFT_MSG_NEWGEN, on_gen, &id);
    return id;
}

// ---- tables ----
typedef struct { char name[NAME_LEN]; uint8_t family; char marker[NAME_LEN]; } Table;
typedef struct { const char *prefix; const char *exact; Table t[MAX_TABLES]; int n; int others; } TableScan;

static void on_table(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    TableScan *s = ctx;
    const struct nfgenmsg *ng = NLMSG_DATA(h);
    Attrs a;
    parse_attrs(&a, p, n);
    char name[NAME_LEN];
    attr_str(a.a[NFTA_TABLE_NAME], name, sizeof(name));
    int match = s->exact ? strcmp(name, s->exact) == 0 : strncmp(name, s->prefix, strlen(s->prefix)) == 0;
    if (!match) { s->others++; return; }
    if (s->n >= MAX_TABLES) die(EXIT_MALFORMED, "too many matching tables");
    Table *t = &s->t[s->n++];
    memset(t, 0, sizeof(*t));
    memcpy(t->name, name, sizeof(name));
    t->family = ng->nfgen_family;
    const struct nlattr *ud = a.a[NFTA_TABLE_USERDATA];
    if (ud) {
        size_t len = attr_len(ud);
        if (len >= sizeof(t->marker)) len = sizeof(t->marker) - 1;
        const unsigned char *b = attr_data(ud);
        for (size_t i = 0; i < len; i++) t->marker[i] = (b[i] >= 0x21 && b[i] < 0x7f) ? (char)b[i] : '.';
    }
}

// ---- chains ----
typedef struct { const Table *t; } ChainCtx;

static void on_chain(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    (void)h;
    ChainCtx *c = ctx;
    Attrs a;
    parse_attrs(&a, p, n);
    char table[NAME_LEN], name[NAME_LEN], type[NAME_LEN] = "-";
    attr_str(a.a[NFTA_CHAIN_TABLE], table, sizeof(table));
    if (strcmp(table, c->t->name) != 0) return;
    attr_str(a.a[NFTA_CHAIN_NAME], name, sizeof(name));
    if (a.a[NFTA_CHAIN_TYPE]) attr_str(a.a[NFTA_CHAIN_TYPE], type, sizeof(type));
    printf("chain %s %s type=%s", table, name, type);
    if (a.a[NFTA_CHAIN_HOOK]) {
        Attrs hk;
        parse_attrs(&hk, attr_data(a.a[NFTA_CHAIN_HOOK]), attr_len(a.a[NFTA_CHAIN_HOOK]));
        printf(" hook=%u prio=%d", attr_u32(hk.a[NFTA_HOOK_HOOKNUM]), (int32_t)attr_u32(hk.a[NFTA_HOOK_PRIORITY]));
    }
    if (a.a[NFTA_CHAIN_POLICY]) printf(" policy=%s", attr_u32(a.a[NFTA_CHAIN_POLICY]) == NF_ACCEPT ? "accept" : "drop");
    printf("\n");
}

// ---- sets ----
typedef struct { char name[NAME_LEN]; uint32_t flags, key_len; } Set;
typedef struct { const Table *t; Set s[MAX_SETS]; int n; } SetScan;

static void on_set(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    (void)h;
    SetScan *s = ctx;
    Attrs a;
    parse_attrs(&a, p, n);
    char table[NAME_LEN];
    attr_str(a.a[NFTA_SET_TABLE], table, sizeof(table));
    if (strcmp(table, s->t->name) != 0) return;
    if (s->n >= MAX_SETS) die(EXIT_MALFORMED, "too many sets");
    Set *e = &s->s[s->n++];
    attr_str(a.a[NFTA_SET_NAME], e->name, sizeof(e->name));
    e->flags = a.a[NFTA_SET_FLAGS] ? attr_u32(a.a[NFTA_SET_FLAGS]) : 0;
    e->key_len = attr_u32(a.a[NFTA_SET_KEY_LEN]);
}

// ---- set elements ----
typedef struct { int set_index; long long base_ms; uint8_t key_len; unsigned char key[16]; uint64_t timeout_ms, expires_ms; int has_timeout, has_expiry; } Elem;
typedef struct { const char *table; const char *set; int set_index; uint32_t key_len; long long base_ms; Elem *e; size_t n; } ElemScan;

static void on_elems(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    (void)h;
    ElemScan *s = ctx;
    Attrs a;
    parse_attrs(&a, p, n);
    char table[NAME_LEN], set[NAME_LEN];
    attr_str(a.a[NFTA_SET_ELEM_LIST_TABLE], table, sizeof(table));
    attr_str(a.a[NFTA_SET_ELEM_LIST_SET], set, sizeof(set));
    if (strcmp(table, s->table) != 0 || strcmp(set, s->set) != 0) die(EXIT_MALFORMED, "element dump for another set");
    const struct nlattr *list = a.a[NFTA_SET_ELEM_LIST_ELEMENTS];
    if (!list) return;
    const unsigned char *q = attr_data(list);
    size_t left = attr_len(list);
    while (left > 0) {
        if (left < NLA_HDRLEN) die(EXIT_MALFORMED, "truncated element list");
        const struct nlattr *item = (const struct nlattr *)q;
        if (item->nla_len < NLA_HDRLEN || item->nla_len > left) die(EXIT_MALFORMED, "element length out of bounds");
        if ((item->nla_type & NLA_TYPE_MASK) != NFTA_LIST_ELEM) die(EXIT_MALFORMED, "unexpected element list entry");
        Attrs e;
        parse_attrs(&e, attr_data(item), attr_len(item));
        if (s->n >= MAX_ELEMS) die(EXIT_MALFORMED, "too many elements");
        Elem *out = &s->e[s->n++];
        memset(out, 0, sizeof(*out));
        out->set_index = s->set_index;
        out->base_ms = s->base_ms;
        size_t klen = nested_value(e.a[NFTA_SET_ELEM_KEY], out->key, sizeof(out->key));
        if (klen != s->key_len || (klen != 4 && klen != 16)) die(EXIT_MALFORMED, "unexpected key length");
        out->key_len = (uint8_t)klen;
        uint32_t flags = e.a[NFTA_SET_ELEM_FLAGS] ? attr_u32(e.a[NFTA_SET_ELEM_FLAGS]) : 0;
        if (flags & NFT_SET_ELEM_INTERVAL_END) die(EXIT_MALFORMED, "interval element in an address set");
        if (e.a[NFTA_SET_ELEM_TIMEOUT]) { out->has_timeout = 1; out->timeout_ms = attr_u64(e.a[NFTA_SET_ELEM_TIMEOUT]); }
        if (e.a[NFTA_SET_ELEM_EXPIRATION]) { out->has_expiry = 1; out->expires_ms = attr_u64(e.a[NFTA_SET_ELEM_EXPIRATION]); }
        size_t step = NLA_ALIGN(item->nla_len);
        if (step > left) step = left;
        q += step;
        left -= step;
    }
}

static int elem_cmp(const void *x, const void *y) {
    const Elem *a = x, *b = y;
    if (a->key_len != b->key_len) return a->key_len - b->key_len;
    int c = memcmp(a->key, b->key, a->key_len);
    if (c) return c;
    return a->set_index - b->set_index;
}

static void format_addr(const unsigned char *key, size_t len, char *out, size_t cap) {
    if (!inet_ntop(len == 4 ? AF_INET : AF_INET6, key, out, (socklen_t)cap)) die(EXIT_MALFORMED, "address format");
}

// ---- rules ----
// Decodes only the matches needed to identify an address ban: set lookup, source address
// (with optional prefix mask), layer-4 protocol, destination port range and verdict.
typedef struct { const Table *t; int scoped; int lookups; int rules; } RuleCtx;

static int popcount_bytes(const unsigned char *m, size_t n) {
    int bits = 0;
    for (size_t i = 0; i < n; i++) bits += __builtin_popcount(m[i]);
    return bits;
}

static void on_rule(const struct nlmsghdr *h, const void *p, size_t n, void *ctx) {
    (void)h;
    RuleCtx *c = ctx;
    Attrs a;
    parse_attrs(&a, p, n);
    char table[NAME_LEN], chain[NAME_LEN];
    attr_str(a.a[NFTA_RULE_TABLE], table, sizeof(table));
    if (strcmp(table, c->t->name) != 0) return;
    attr_str(a.a[NFTA_RULE_CHAIN], chain, sizeof(chain));
    uint64_t handle = attr_u64(a.a[NFTA_RULE_HANDLE]);
    c->rules++;
    char lookup[NAME_LEN] = "", saddr[64] = "", verdict[16] = "none";
    int lookup_inverted = 0;
    int proto = -1, port_lo = -1, port_hi = -1;
    enum { LOAD_NONE, LOAD_SADDR, LOAD_L4PROTO, LOAD_DPORT, LOAD_OTHER } load = LOAD_NONE;
    size_t addr_len = 0;
    unsigned char mask[16];
    int masked = 0;
    const struct nlattr *exprs = a.a[NFTA_RULE_EXPRESSIONS];
    const unsigned char *q = exprs ? attr_data(exprs) : NULL;
    size_t left = exprs ? attr_len(exprs) : 0;
    while (left > 0) {
        if (left < NLA_HDRLEN) die(EXIT_MALFORMED, "truncated expression list");
        const struct nlattr *item = (const struct nlattr *)q;
        if (item->nla_len < NLA_HDRLEN || item->nla_len > left) die(EXIT_MALFORMED, "expression length out of bounds");
        Attrs e;
        parse_attrs(&e, attr_data(item), attr_len(item));
        char ename[32];
        attr_str(e.a[NFTA_EXPR_NAME], ename, sizeof(ename));
        Attrs d;
        memset(&d, 0, sizeof(d));
        if (e.a[NFTA_EXPR_DATA]) parse_attrs(&d, attr_data(e.a[NFTA_EXPR_DATA]), attr_len(e.a[NFTA_EXPR_DATA]));
        if (strcmp(ename, "lookup") == 0) {
            attr_str(d.a[NFTA_LOOKUP_SET], lookup, sizeof(lookup));
            if (d.a[NFTA_LOOKUP_FLAGS] && (attr_u32(d.a[NFTA_LOOKUP_FLAGS]) & NFT_LOOKUP_F_INV)) lookup_inverted = 1;
        } else if (strcmp(ename, "meta") == 0) {
            uint32_t key = attr_u32(d.a[NFTA_META_KEY]);
            load = key == NFT_META_L4PROTO ? LOAD_L4PROTO : LOAD_OTHER;
        } else if (strcmp(ename, "payload") == 0) {
            uint32_t base = attr_u32(d.a[NFTA_PAYLOAD_BASE]), off = attr_u32(d.a[NFTA_PAYLOAD_OFFSET]), len = attr_u32(d.a[NFTA_PAYLOAD_LEN]);
            masked = 0;
            if (base == NFT_PAYLOAD_NETWORK_HEADER && ((off == 12 && len == 4) || (off == 8 && len == 16))) { load = LOAD_SADDR; addr_len = len; }
            else if (base == NFT_PAYLOAD_TRANSPORT_HEADER && off == 2 && len == 2) load = LOAD_DPORT;
            else load = LOAD_OTHER;
        } else if (strcmp(ename, "bitwise") == 0) {
            if (load == LOAD_SADDR) {
                size_t mlen = nested_value(d.a[NFTA_BITWISE_MASK], mask, sizeof(mask));
                if (mlen != addr_len) die(EXIT_MALFORMED, "mask length mismatch");
                masked = 1;
            }
        } else if (strcmp(ename, "cmp") == 0) {
            unsigned char v[16];
            size_t vlen = nested_value(d.a[NFTA_CMP_DATA], v, sizeof(v));
            uint32_t op = attr_u32(d.a[NFTA_CMP_OP]);
            if (load == LOAD_SADDR && op == NFT_CMP_EQ && vlen == addr_len) {
                char text[INET6_ADDRSTRLEN];
                format_addr(v, vlen, text, sizeof(text));
                snprintf(saddr, sizeof(saddr), "%s/%d", text, masked ? popcount_bytes(mask, addr_len) : (int)addr_len * 8);
            } else if (load == LOAD_L4PROTO && vlen == 1) {
                proto = v[0];
            } else if (load == LOAD_DPORT && vlen == 2) {
                int port = (v[0] << 8) | v[1];
                if (op == NFT_CMP_EQ) port_lo = port_hi = port;
                else if (op == NFT_CMP_GTE) port_lo = port;
                else if (op == NFT_CMP_LTE) port_hi = port;
            }
        } else if (strcmp(ename, "immediate") == 0 && d.a[NFTA_IMMEDIATE_DATA]) {
            Attrs data, v;
            parse_attrs(&data, attr_data(d.a[NFTA_IMMEDIATE_DATA]), attr_len(d.a[NFTA_IMMEDIATE_DATA]));
            if (data.a[NFTA_DATA_VERDICT]) {
                parse_attrs(&v, attr_data(data.a[NFTA_DATA_VERDICT]), attr_len(data.a[NFTA_DATA_VERDICT]));
                int32_t code = (int32_t)attr_u32(v.a[NFTA_VERDICT_CODE]);
                snprintf(verdict, sizeof(verdict), "%s", code == NF_DROP ? "drop" : code == NF_ACCEPT ? "accept" : "other");
            }
        }
        size_t step = NLA_ALIGN(item->nla_len);
        if (step > left) step = left;
        q += step;
        left -= step;
    }
    printf("rule %s %s handle=%llu", table, chain, (unsigned long long)handle);
    if (lookup[0]) { printf(" lookup=%s%s", lookup_inverted ? "!" : "", lookup); c->lookups++; }
    if (saddr[0]) {
        printf(" saddr=%s proto=", saddr);
        if (proto >= 0) printf("%d", proto); else printf("any");
        if (port_lo >= 0 || port_hi >= 0) printf(" dport=%d-%d", port_lo, port_hi); else printf(" dport=any");
        c->scoped++;
    }
    printf(" verdict=%s userdata=%s\n", verdict, a.a[NFTA_RULE_USERDATA] ? "yes" : "no");
}

int main(int argc, char **argv) {
    const char *prefix = "f2z_", *exact = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--prefix") == 0 && i + 1 < argc) prefix = argv[++i];
        else if (strcmp(argv[i], "--table") == 0 && i + 1 < argc) exact = argv[++i];
        else { fprintf(stderr, "usage: kernel_oracle [--prefix NAME_PREFIX | --table NAME]\n"); return EXIT_USAGE; }
    }
    rx = malloc(RX_SIZE);
    Elem *elems = calloc(MAX_ELEMS, sizeof(Elem));
    if (!rx || !elems) die(EXIT_NL, "out of memory");
    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (fd < 0) die(EXIT_NL, "socket(NETLINK_NETFILTER) failed");
    int rcv = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, sizeof(rcv));
    struct timeval tv = { .tv_sec = 5 };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) die(EXIT_NL, "SO_RCVTIMEO failed");
    struct sockaddr_nl local = { .nl_family = AF_NETLINK };
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) != 0) die(EXIT_NL, "bind failed");

    long long now_ms = wall_ms();
    uint32_t gen_before = generation();

    static TableScan tables;
    tables.prefix = prefix;
    tables.exact = exact;
    request(NFT_MSG_GETTABLE, NLM_F_DUMP, NFPROTO_UNSPEC, NULL, 0, NFT_MSG_NEWTABLE, on_table, &tables);

    printf("now_ms %lld\n", now_ms);
    printf("genid %u\n", gen_before);
    size_t total_elems = 0, counted_elems = 0;
    int scoped = 0;
    char per_set[1024] = "";
    size_t per_set_len = 0;
    static SetScan sets;
    for (int ti = 0; ti < tables.n; ti++) {
        const Table *t = &tables.t[ti];
        printf("table family=%u %s marker=%s\n", t->family, t->name, t->marker[0] ? t->marker : "-");
        unsigned char attrs[NAME_LEN * 2 + 16] __attribute__((aligned(4)));

        ChainCtx cc = { t };
        request(NFT_MSG_GETCHAIN, NLM_F_DUMP, t->family, NULL, 0, NFT_MSG_NEWCHAIN, on_chain, &cc);

        memset(&sets, 0, sizeof(sets));
        sets.t = t;
        size_t alen = put_str_attr(attrs, 0, NFTA_SET_TABLE, t->name);
        request(NFT_MSG_GETSET, NLM_F_DUMP, t->family, attrs, alen, NFT_MSG_NEWSET, on_set, &sets);

        size_t first = total_elems;
        for (int si = 0; si < sets.n; si++) {
            // Anonymous sets belong to rule expressions, not to the ban inventory.
            if (sets.s[si].flags & NFT_SET_ANONYMOUS) {
                printf("set %s %s flags=0x%x key_len=%u anonymous=skipped\n", t->name, sets.s[si].name, sets.s[si].flags, sets.s[si].key_len);
                continue;
            }
            // Deadlines are computed from the dump start; latency bounds their bias.
            long long start_ms = wall_ms();
            ElemScan es = { t->name, sets.s[si].name, si, sets.s[si].key_len, start_ms, elems + total_elems, 0 };
            alen = put_str_attr(attrs, 0, NFTA_SET_ELEM_LIST_TABLE, t->name);
            alen = put_str_attr(attrs, alen, NFTA_SET_ELEM_LIST_SET, sets.s[si].name);
            request(NFT_MSG_GETSETELEM, NLM_F_DUMP, t->family, attrs, alen, NFT_MSG_NEWSETELEM, on_elems, &es);
            total_elems += es.n;
            counted_elems += es.n;
            printf("set %s %s flags=0x%x key_len=%u elements=%zu dump_start_ms=%lld dump_latency_ms=%lld\n", t->name, sets.s[si].name,
                   sets.s[si].flags, sets.s[si].key_len, es.n, start_ms, wall_ms() - start_ms);
            int w = snprintf(per_set + per_set_len, sizeof(per_set) - per_set_len, "%s%s:%zu", per_set_len ? "," : "", sets.s[si].name, es.n);
            if (w < 0 || (size_t)w >= sizeof(per_set) - per_set_len) die(EXIT_MALFORMED, "too many sets for summary");
            per_set_len += (size_t)w;
        }
        qsort(elems + first, total_elems - first, sizeof(Elem), elem_cmp);
        for (size_t i = first; i < total_elems; i++) {
            const Elem *e = &elems[i];
            char text[INET6_ADDRSTRLEN];
            format_addr(e->key, e->key_len, text, sizeof(text));
            printf("elem %s/%d set=%s", text, e->key_len * 8, sets.s[e->set_index].name);
            if (e->has_timeout) printf(" timeout_ms=%llu", (unsigned long long)e->timeout_ms); else printf(" timeout_ms=-");
            if (e->has_expiry) printf(" expires_ms=%llu deadline_ms=%lld", (unsigned long long)e->expires_ms, e->base_ms + (long long)e->expires_ms);
            else printf(" expires_ms=- deadline_ms=-");
            printf("\n");
        }

        RuleCtx rc = { t, 0, 0, 0 };
        alen = put_str_attr(attrs, 0, NFTA_RULE_TABLE, t->name);
        request(NFT_MSG_GETRULE, NLM_F_DUMP, t->family, attrs, alen, NFT_MSG_NEWRULE, on_rule, &rc);
        scoped += rc.scoped;
    }
    uint32_t gen_after = generation();
    if (gen_after != gen_before) {
        fprintf(stderr, "kernel_oracle: ruleset generation changed %u -> %u during dump\n", gen_before, gen_after);
        return EXIT_CHANGED;
    }
    printf("summary tables=%d other_tables=%d elements=%zu scoped_rules=%d sets=%s\n", tables.n, tables.others, counted_elems, scoped, per_set_len ? per_set : "-");
    fflush(stdout);
    if (ferror(stdout)) return EXIT_NL;
    return 0;
}
