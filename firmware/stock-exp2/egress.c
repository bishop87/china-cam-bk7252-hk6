/* HK6 stock EXP2 research: IPv4 output policy, no heap or persistent state.
 * Layouts verified against the pinned lwIP SDK and vendor disassembly.
 * NTP exception: exact pool DNS question and cached destination, standard request.
 */
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
struct pbuf_view { void *next; const u8 *payload; u16 total, len; };
struct netif_view { void *next; u32 address, mask; };
static u32 address(const u8 *p) {
    return ((u32)p[0]<<24)|((u32)p[1]<<16)|((u32)p[2]<<8)|p[3];
}
/* Vendor DNS table verified at 0x699e0..0x69a1a: four 272-byte entries,
 * name +16, state +10 (DONE=3), IPv4 +4, TTL +0. Server array: 0x407a70.
 * Called on lwIP output path; no resolver call, allocation or new global RAM.
 */
const char hk6_ntp_name[] = "europe.pool.ntp.org";
static int equal_name(const volatile u8 *s) {
    u32 i;
    for (i=0; i<sizeof(hk6_ntp_name); ++i) {
        u8 c=s[i];
        if (c>='A' && c<='Z') c += 'a'-'A';
        if (c!=(u8)hk6_ntp_name[i]) return 0;
    }
    return 1;
}
static int cached_ntp(u32 dst) {
    u32 i;
    for (i=0;i<4;++i) {
        const volatile u8 *e=(const volatile u8 *)(0x407630U+i*272U);
        if (e[10]==3 && *(const volatile u32 *)e!=0 && equal_name(e+16) &&
            address((const u8 *)(e+4))==dst) return 1;
    }
    return 0;
}
static int pool_dns(const struct pbuf_view *p, u32 dst) {
    static const u8 question[]={6,'e','u','r','o','p','e',4,'p','o','o','l',
                              3,'n','t','p',3,'o','r','g',0,0,1,0,1};
    const u8 *q=p->payload;
    const u8 *servers=(const u8 *)0x407a70U;
    u32 i, bytes=8+12+sizeof(question);
    if (!dst || (dst!=address(servers) && dst!=address(servers+4))) return 0;
    if (p->total!=bytes || p->len<bytes || q[4] || q[5]!=bytes) return 0;
    /* DNS query: RD set, one A/IN question, no answers/authority/additional. */
    if (q[10]!=1 || q[11] || q[12] || q[13]!=1) return 0;
    for(i=14;i<20;++i) if(q[i]) return 0;
    for(i=0;i<sizeof(question);++i) if(q[20+i]!=question[i]) return 0;
    return 1;
}
static int ntp_request(const struct pbuf_view *p,u32 dst) {
    u32 offset=0, i;
    const u8 *q=p->payload;
    /* lwIP socket sends can prepend a separate 8-byte UDP header pbuf.
     * Validate the whole single packet without copying or altering buffers.
     * Positive lengths and decreasing remaining total bound traversal to 56
     * nodes, including malformed/cyclic chains. Never cross a packet queue.
     */
    if (p->total!=56 || p->len<8 || q[4] || q[5]!=56) return 0;
    while (p) {
        if (!p->payload || !p->len || p->total!=56-offset ||
            p->len>p->total) return 0;
        q=p->payload;
        for (i=0;i<p->len;++i,++offset) {
            if (offset==8 && q[i]!=0x1b) return 0;
            if (offset>8 && q[i]) return 0;
        }
        p=(const struct pbuf_view *)p->next;
        if (offset==56) {
            if (p) return 0;
            break;
        }
    }
    if (offset!=56) return 0;
    return cached_ntp(dst);
}
int hk6_packet_allowed(const struct pbuf_view *p, const u8 *dest,
                       const struct netif_view *netif, u32 protocol) {
    u32 dst, own, mask, inv;
    u16 sport=0, dport=0;
    if (!p || !p->payload || !dest || !netif) return 0;
    /* IP_HDRINCL (dest == NULL) is denied: no unchecked alternate parsing. */
    dst=address(dest);
    if (protocol==6 || protocol==17) {
        if (p->len<4) return 0;
        sport=((u16)p->payload[0]<<8)|p->payload[1];
        dport=((u16)p->payload[2]<<8)|p->payload[3];
        /* Also stop external-name lookups forwarded by a LAN resolver. */
        if (dport==53) return protocol==17 && pool_dns(p,dst);
    }
    /* DHCP acquisition before the interface has its IPv4 configuration. */
    if (protocol==17 && sport==68 && dport==67 && dst==0xffffffffU) return 1;
    own=address((const u8 *)&netif->address);
    mask=address((const u8 *)&netif->mask);
    inv=~mask;
    if (!own || !mask || (inv & (inv+1))) return 0;
    if (!dst || (dst & 0xf0000000U)==0xe0000000U) return 0;
    /* Preserve local UDP discovery on limited broadcast. */
    if (dst==0xffffffffU) return protocol==17;
    if (((dst ^ own) & mask)==0) return 1;
    return protocol==17 && dport==123 && ntp_request(p,dst);
}
