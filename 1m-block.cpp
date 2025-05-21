#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>    /* for NF_ACCEPT */
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <string.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <set>
#include <sys/sysinfo.h>

clock_t elapsed;
float   sec;
#define START_TIME    (elapsed = -clock())
#define STOP_TIME     (elapsed += clock(), sec = (float)elapsed/CLOCKS_PER_SEC)
#define PRINT_TIME(s) printf("\n[%-23s: %2.5f s]\n\n", s, sec)

typedef struct {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4, version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4, ihl:4;
#endif
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  proto;
    uint16_t check;
    uint32_t s_addr;
    uint32_t d_addr;
} IpHdr;

typedef struct {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq;
    uint32_t ack;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t reserved:4, doff:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t doff:4, reserved:4;
#endif
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urgptr;
} TcpHdr;

char          argcCount;
std::set<std::string> blockedSites;

char *strnstr(const char *src, const char *pat, int len) {
    int patlen = strlen(pat);
    if (patlen == 0) return (char*)src;
    char *tmp = (char*)malloc(len+1);
    strncpy(tmp, src, len);
    tmp[len] = '\0';
    char *found = strstr(tmp, pat);
    free(tmp);
    return found;
}

void dumpHex(unsigned char* buf, int sz) {
    for (int i = 0; i < sz; ++i) {
        if (i && i % 16 == 0) printf("\n");
        printf("%02X ", buf[i]);
    }
    printf("\n");
}

static uint32_t print_pkt(struct nfq_data *tb) {
    uint32_t pkt_id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    if (ph) pkt_id = ntohl(ph->packet_id);
    return pkt_id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    uint32_t id = print_pkt(nfa);
    unsigned char *pkt;
    if (nfq_get_payload(nfa, &pkt) < 0)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    IpHdr  *ip   = (IpHdr*)pkt;
    if (ip->proto != 0x06)
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    TcpHdr *tcp  = (TcpHdr*)(pkt + ip->ihl * 4);
    const char *http = (char*)(pkt + ip->ihl*4 + tcp->doff*4);

    char *hostPtr = nullptr;
    if (ntohs(tcp->dport) == 80
        && !strncmp(http, "GET", 3)
        && (hostPtr = strnstr(http, "Host: ", 100))) {
        START_TIME;
        std::string site(hostPtr + 6);
        std::istringstream iss(site);
        std::getline(iss, site, '\r');
        if (blockedSites.count(site)) {
            printf("\nBlocked site detected: %s\n", site.c_str());
            STOP_TIME; PRINT_TIME("Lookup duration");
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
        STOP_TIME; PRINT_TIME("Lookup duration");
    }

    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

void showSysinfo(struct sysinfo *s, unsigned long *used) {
    printf(" Uptime       : %ld seconds\n", s->uptime);
    printf(" Total RAM    : %lu bytes\n", s->totalram);
    printf(" Free RAM     : %lu bytes\n", s->freeram);
    printf(" Processes    : %u\n", s->procs);
    *used = s->totalram - s->freeram;
}

int main(int argc, char **argv) {
    struct sysinfo si;
    unsigned long memBefore, memAfter;

    // --- 초기 시스템 정보 ---
    sysinfo(&si);
    printf("[Before loading list]\n");
    showSysinfo(&si, &memBefore);

    if (argc < 2) {
        fprintf(stderr,
            "Usage: %s <site-list.txt>\n"
            "Example: %s top-1m.txt\n",
            argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    argcCount = argc;

    // --- 블록 리스트 로딩 ---
    START_TIME;
    std::ifstream infile(argv[1]);
    if (!infile) {
        fprintf(stderr, "Cannot open '%s'\n", argv[1]);
        return EXIT_FAILURE;
    }
    std::string idx, domain;
    while (std::getline(infile, idx, ',') &&
           std::getline(infile, domain)) {
        blockedSites.insert(domain);
    }
    infile.close();
    STOP_TIME;
    PRINT_TIME("Load & parse");

    sysinfo(&si);
    printf("[After loading list]\n");
    showSysinfo(&si, &memAfter);
    printf("Memory used for list: %lu bytes\n\n", memAfter - memBefore);

    // --- NFQ 초기화 ---
    nfq_handle *h = nfq_open();
    if (!h) {
        perror("nfq_open");
        exit(EXIT_FAILURE);
    }
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);

    nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, nullptr);
    if (!qh) {
        perror("nfq_create_queue");
        nfq_close(h);
        exit(EXIT_FAILURE);
    }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);

    printf("Ready to intercept packets...\n");

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));
    while (true) {
        int ret = recv(fd, buf, sizeof(buf), 0);
        if (ret >= 0) {
            nfq_handle_packet(h, buf, ret);
        } else if (errno == ENOBUFS) {
            printf("Warning: packet loss\n");
        } else {
            perror("recv");
            break;
        }
    }

    // --- 정리 ---
    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}

