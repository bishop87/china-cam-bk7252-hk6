/* HTTP transport is independent of stock addresses and frame acquisition.
 * One session-owned slot. IRQ exclusion protects transitions, never I/O/copy.
 */
#include "http.h"
static uint32_t length(const char *s) { uint32_t n=0; while(s[n]) ++n; return n; }
static void copy(void *dst,const void *src,uint32_t n) {
    uint8_t *d=dst; const uint8_t *s=src; while(n--) *d++=*s++;
}
static int equal(const char *a,const char *b) {
    while(*a && *a==*b) { ++a; ++b; } return *a==*b;
}
static int expired(uint32_t start,uint32_t ms) { return (uint32_t)(hk6_now()-start)>=ms; }
static int send_bytes(int fd,const void *p,uint32_t n,uint32_t start) {
    const uint8_t *s=p;
    while(n) {
        uint32_t chunk=n>1024?1024:n;
        int sent;
        if(expired(start,3000)) return -1;
        sent=hk6_send(fd,s,chunk);
        if(sent<=0 || (uint32_t)sent>chunk) return -1;
        s+=sent; n-=(uint32_t)sent;
    }
    return expired(start,3000)?-1:0;
}
static int text(int fd,const char *s,uint32_t start) { return send_bytes(fd,s,length(s),start); }
static char *decimal(char *p,uint32_t n) {
    char temp[10]; unsigned i=0;
    do { temp[i++]=(char)('0'+n%10); n/=10; } while(n);
    while(i) *p++=temp[--i]; *p=0; return p;
}
static int response(int fd,const char *status,const char *type,const void *body,uint32_t n) {
    char number[11]; uint32_t start=hk6_now(); decimal(number,n);
    return text(fd,"HTTP/1.0 ",start) || text(fd,status,start) ||
      text(fd,"\r\nContent-Type: ",start) || text(fd,type,start) ||
      text(fd,"\r\nContent-Length: ",start) || text(fd,number,start) ||
      text(fd,"\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",start) ||
      send_bytes(fd,body,n,start);
}
static void error(int fd,const char *status) { (void)response(fd,status,"text/plain",status,length(status)); }

void hk6_offer(struct hk6_state *s,const uint8_t *frame,uint32_t n) {
    uint32_t key; uint8_t *dest;
    if(!s || !frame || n<7 || n>HK6_FRAME_CAP) return;
    if(frame[0]!=255 || frame[1]!=216 || frame[n-7]!=255 || frame[n-6]!=217) return;
    if(((uint32_t)frame[n-4] | ((uint32_t)frame[n-3]<<8) |
        ((uint32_t)frame[n-2]<<16) | ((uint32_t)frame[n-1]<<24))!=n-5) return;
    key=hk6_lock();
    if(!s->active || !s->want || s->phase!=HK6_EMPTY || !s->frame) {
        if(s->active) ++s->dropped;
        hk6_unlock(key); return;
    }
    s->phase=HK6_COPYING; s->want=0; dest=s->frame;
    hk6_unlock(key);
    copy(dest,frame,n-5);
    key=hk6_lock(); s->length=n-5;
    s->phase=s->active?HK6_READY:HK6_EMPTY;
    hk6_unlock(key);
}
int hk6_needed(void) {
    struct hk6_state *s=hk6_lookup(); uint32_t key; int needed;
    if(!s) return 0;
    key=hk6_lock(); needed=s->active && s->want && s->phase==HK6_EMPTY;
    hk6_unlock(key); return needed;
}
static int begin(struct hk6_state *s) {
    uint8_t *p=hk6_alloc(HK6_FRAME_CAP); uint32_t key;
    if(!p) return -1;
    key=hk6_lock(); s->frame=p; s->length=0; s->phase=HK6_EMPTY;
    s->want=1; s->active=1; hk6_unlock(key); return 0;
}
static void end(struct hk6_state *s) {
    uint32_t key=hk6_lock(); uint8_t *p;
    s->active=0; s->want=0; hk6_unlock(key);
    /* Only worker frees; producer may still be finishing a bounded copy. */
    for(;;) {
        key=hk6_lock();
        if(s->phase!=HK6_COPYING) break;
        hk6_unlock(key); hk6_delay(1);
    }
    p=s->frame; s->frame=0; s->phase=HK6_EMPTY; s->length=0;
    hk6_unlock(key); hk6_free(p);
}
static int wait_frame(struct hk6_state *s) {
    uint32_t start=hk6_now();
    while(!expired(start,2500)) {
        uint32_t key=hk6_lock();
        if(s->phase==HK6_READY) { s->phase=HK6_SENDING; hk6_unlock(key); return 0; }
        hk6_unlock(key); hk6_delay(10);
    }
    return -1;
}
static void video(struct hk6_state *s,int fd,int stream) {
    const char *header="HTTP/1.0 200 OK\r\nContent-Type: multipart/x-mixed-replace; boundary=hk6\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";
    if(begin(s)) { error(fd,"503 Service Unavailable"); return; }
    if(wait_frame(s)) { error(fd,"503 Service Unavailable"); end(s); return; }
    if(!stream) { (void)response(fd,"200 OK","image/jpeg",s->frame,s->length); end(s); return; }
    if(text(fd,header,hk6_now())) { end(s); return; }
    for(;;) {
        char number[11]; uint32_t start=hk6_now(),key;
        decimal(number,s->length);
        if(text(fd,"--hk6\r\nContent-Type: image/jpeg\r\nContent-Length: ",start) ||
           text(fd,number,start) || text(fd,"\r\n\r\n",start) ||
           send_bytes(fd,s->frame,s->length,start) || text(fd,"\r\n",start)) break;
        ++s->delivered;
        hk6_delay(200); /* at most five requests per second */
        key=hk6_lock(); s->phase=HK6_EMPTY; s->want=1; hk6_unlock(key);
        if(wait_frame(s)) break;
    }
    end(s);
}
void hk6_serve(struct hk6_state *s,int fd) {
    char request[HK6_REQUEST_CAP]; uint32_t used=0,start=hk6_now(),i; int complete=0;
    if(hk6_timeouts(fd)) return;
    while(used<sizeof(request)-1 && !expired(start,3000)) {
        int n=hk6_recv(fd,request+used,(uint32_t)sizeof(request)-1-used);
        if(n<=0 || (uint32_t)n>sizeof(request)-1-used) return;
        for(i=used;i<used+(uint32_t)n;++i) if(!request[i]) { error(fd,"400 Bad Request"); return; }
        used+=(uint32_t)n; request[used]=0;
        for(i=3;i<used;++i) if(request[i-3]=='\r' && request[i-2]=='\n' && request[i-1]=='\r' && request[i]=='\n') { complete=1; break; }
        if(complete) break;
    }
    if(!complete || expired(start,3000)) { error(fd,"431 Request Header Fields Too Large"); return; }
    for(i=0;i+1<used;++i) if(request[i]=='\r' && request[i+1]=='\n') { request[i]=0; break; }
    if(equal(request,"GET / HTTP/1.1") || equal(request,"GET / HTTP/1.0")) {
        static const char page[]="<!doctype html><meta name=viewport content='width=device-width'><title>HK6 LAN</title><style>body{background:#111;color:#eee;font-family:sans-serif}img{max-width:100%}</style><h1>HK6 LAN</h1><img src='/stream.mjpg' alt='Video'><p><a href='/'>Riconnetti</a> · <a href='/snapshot.jpg'>Snapshot</a></p>";
        (void)response(fd,"200 OK","text/html; charset=utf-8",page,sizeof(page)-1);
    } else if(equal(request,"GET /snapshot.jpg HTTP/1.1") || equal(request,"GET /snapshot.jpg HTTP/1.0")) video(s,fd,0);
    else if(equal(request,"GET /stream.mjpg HTTP/1.1") || equal(request,"GET /stream.mjpg HTTP/1.0")) video(s,fd,1);
    else error(fd,"404 Not Found");
}
