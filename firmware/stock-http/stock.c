/* EXP2F-only ABI. No mutable globals: state is a persistent thread parameter. */
#include "http.h"
#define FN(addr,type) ((type)(uintptr_t)((addr)|1u))
uint32_t hk6_lock(void) { return FN(0xb723c,uint32_t(*)(void))(); }
void hk6_unlock(uint32_t key) { FN(0xb7198,void(*)(uint32_t))(key); }
uint32_t hk6_now(void) { return FN(0x5b1a0,uint32_t(*)(void))(); }
void hk6_delay(uint32_t ms) { FN(0x5d27c,void(*)(uint32_t))(ms); }
void *hk6_alloc(uint32_t n) {
    /* Explicit main heap, never silently consume TCM video/thread resources. */
    return FN(0x5c610,void *(*)(void *,uint32_t))((void *)0x40ec28,n);
}
void hk6_free(void *p) { if(p) FN(0x5c734,void(*)(void *))(p); }
struct hk6_state *hk6_lookup(void) {
    uint8_t *t=FN(0x5d378,void *(*)(const char *))("hk6http");
    return t?*(struct hk6_state **)(t+0x24):0;
}
int hk6_send(int fd,const void *p,uint32_t n) { return FN(0x68824,int(*)(int,const void *,uint32_t,int))(fd,p,n,0); }
int hk6_recv(int fd,void *p,uint32_t n) { return FN(0x6871e,int(*)(int,void *,uint32_t,int))(fd,p,n,0); }
int hk6_timeouts(int fd) {
    const int32_t timeout[2]={1,0};
    int (*opt)(int,int,int,const void *,int)=FN(0x68c7c,int(*)(int,int,int,const void *,int));
    return opt(fd,0xfff,0x1005,timeout,8) || opt(fd,0xfff,0x1006,timeout,8);
}
static void close_fd(int fd) { (void)FN(0x68348,int(*)(int))(fd); }
static void worker(void *parameter) {
    struct hk6_state *s=parameter;
    for(;;) {
        /* sockaddr is 16 bytes, family byte 1, big-endian port at 2. */
        const uint32_t address[4]={0x50000210u,0,0,0};
        int listener=FN(0x6889c,int(*)(int,int,int))(2,1,0);
        if(listener>=0) {
            int ok=FN(0x682d8,int(*)(int,const void *,int))(listener,address,16);
            if(!ok) ok=FN(0x684ac,int(*)(int,int))(listener,1);
            if(!ok) {
                for(;;) {
                    int fd=FN(0x68148,int(*)(int,void *,void *))(listener,0,0);
                    if(fd<0) break;
                    hk6_serve(s,fd); close_fd(fd);
                }
            }
            close_fd(listener);
        }
        hk6_delay(2000);
    }
}
void hk6_boot(void) {
    void *thread=0;
    struct hk6_state *s=0;
    /* On this seam the stock video thread does not exist yet. Publish the
     * fully initialized parameter before allowing its creation. Never delete
     * our thread/state after publication: producer lookups remain valid. */
    if(!hk6_lookup()) {
        s=hk6_alloc(sizeof(*s));
        if(s) {
            uint32_t i; uint8_t *p=(uint8_t *)s;
            for(i=0;i<sizeof(*s);++i) p[i]=0;
            thread=FN(0x5d0f8,void *(*)(const char *,void(*)(void *),void *,uint32_t,uint8_t,uint32_t))(
                "hk6http",worker,s,4096,21,10);
            if(!thread) { hk6_free(s); s=0; }
        }
    }
    FN(0x1aca8,void(*)(void))(); /* Always preserve native initialization. */
    if(thread) (void)FN(0x5d2e0,int(*)(void *))(thread);
    /* A failed startup keeps small registered state inactive until reboot. */
}
uint32_t hk6_read(uint8_t *p,uint32_t capacity) {
    uint32_t n=FN(0x2837c,uint32_t(*)(uint8_t *,uint32_t))(p,capacity);
    hk6_offer(hk6_lookup(),p,n);
    return n;
}
