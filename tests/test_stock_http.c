#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "../firmware/stock-http/http.h"
static struct hk6_state state;
static uint32_t ticks;
static int locked,fail_alloc,allocations,supply,partial,send_fail,slow,timeout_fail;
static const char *input;
static size_t input_pos,output_len;
static char output[131072];
static uint8_t jpeg[]={255,216,1,2,3,255,217,0,7,0,0,0};
uint32_t hk6_lock(void) { assert(!locked); locked=1; return 77; }
void hk6_unlock(uint32_t key) { assert(locked && key==77); locked=0; }
uint32_t hk6_now(void) { return ticks; }
void hk6_delay(uint32_t n) {
    assert(!locked); ticks+=n;
    if(supply && state.want && state.delivered<2) hk6_offer(&state,jpeg,sizeof(jpeg));
}
void *hk6_alloc(uint32_t n) { assert(!locked); if(fail_alloc)return NULL; ++allocations;return malloc(n); }
void hk6_free(void *p) { assert(!locked); if(p){--allocations;free(p);} }
struct hk6_state *hk6_lookup(void) { return &state; }
int hk6_send(int fd,const void *p,uint32_t n) {
    (void)fd;assert(!locked);
    if(send_fail)return -7;
    if(slow)ticks+=800;
    if(partial && n>3)n=3;
    assert(output_len+n<sizeof(output));memcpy(output+output_len,p,n);output_len+=n;output[output_len]=0;
    if(state.phase==HK6_SENDING) {
        uint8_t before[7];memcpy(before,state.frame,7);
        hk6_offer(&state,jpeg,sizeof(jpeg));assert(!memcmp(before,state.frame,7));
    }
    return (int)n;
}
int hk6_recv(int fd,void *p,uint32_t n) {
    size_t remain=strlen(input)-input_pos;(void)fd;assert(!locked);
    if(!remain)return 0;
    if(n>7)n=7;if(n>remain)n=(uint32_t)remain;
    memcpy(p,input+input_pos,n);input_pos+=n;return (int)n;
}
int hk6_timeouts(int fd) { (void)fd;return timeout_fail; }
static void reset(const char *request) {
    assert(!allocations && !locked);memset(&state,0,sizeof(state));ticks=0;
    fail_alloc=0;supply=1;partial=1;send_fail=0;slow=0;timeout_fail=0;
    input=request;input_pos=output_len=0;output[0]=0;
}
static void done(void) { assert(!allocations && !locked && !state.frame && !state.active && !state.want); }
int main(void) {
    reset("GET / HTTP/1.1\r\nHost: camera\r\n\r\n");hk6_serve(&state,1);
    assert(strstr(output,"200 OK") && strstr(output,"/stream.mjpg"));done();
    reset("GET /snapshot.jpg HTTP/1.1\r\nHost: camera\r\n\r\n");hk6_serve(&state,1);
    assert(strstr(output,"Content-Length: 7\r\n") && !memcmp(output+output_len-7,jpeg,7));done();
    reset("GET /stream.mjpg HTTP/1.0\r\n\r\n");hk6_serve(&state,1);
    assert(state.delivered==2 && state.dropped>0 && strstr(output,"multipart/x-mixed-replace"));done();
    reset("GET /snapshot.jpg HTTP/1.0\r\n\r\n");supply=0;hk6_serve(&state,1);
    assert(strstr(output,"503 Service Unavailable") && ticks==2500);done();
    reset("GET /snapshot.jpg HTTP/1.0\r\n\r\n");fail_alloc=1;hk6_serve(&state,1);
    assert(strstr(output,"503 Service Unavailable"));done();
    reset("GET /stream.mjpg HTTP/1.0\r\n\r\n");send_fail=1;hk6_serve(&state,1);done();
    reset("GET /snapshot.jpg HTTP/1.0\r\n\r\n");slow=1;hk6_serve(&state,1);
    assert(ticks<7000);done();
    reset("GET /snapshot.jpg HTTP/1.0\r\n\r\n");ticks=0xfffffff0u;hk6_serve(&state,1);
    assert(strstr(output,"200 OK"));done();
    reset("GET /stream.mjpgX HTTP/1.0\r\n\r\n");hk6_serve(&state,1);assert(strstr(output,"404"));done();
    reset("GET / HTTP/1.1\r\n\r\n");timeout_fail=1;hk6_serve(&state,1);assert(!output_len);done();
    { char long_request[1100];memset(long_request,'A',sizeof(long_request)-1);long_request[1099]=0;
      reset(long_request);hk6_serve(&state,1);assert(strstr(output,"431"));done(); }
    reset("");
    { uint8_t slot[32];state.frame=slot;state.active=state.want=1;
      hk6_offer(&state,jpeg,6);assert(state.phase==HK6_EMPTY);
      jpeg[8]=8;hk6_offer(&state,jpeg,sizeof(jpeg));assert(state.phase==HK6_EMPTY);jpeg[8]=7;
      assert(hk6_needed());hk6_offer(&state,jpeg,sizeof(jpeg));assert(state.phase==HK6_READY && state.length==7 && !hk6_needed());
      state.frame=0;state.active=state.want=0; }
    done();
    reset("");
    { uint8_t *large=calloc(1,HK6_FRAME_CAP),*slot=malloc(HK6_FRAME_CAP);
      uint32_t payload=HK6_FRAME_CAP-5;
      large[0]=255;large[1]=216;large[HK6_FRAME_CAP-7]=255;large[HK6_FRAME_CAP-6]=217;
      large[HK6_FRAME_CAP-4]=(uint8_t)payload;large[HK6_FRAME_CAP-3]=(uint8_t)(payload>>8);
      state.frame=slot;state.active=state.want=1;
      hk6_offer(&state,large,HK6_FRAME_CAP+1);assert(state.phase==HK6_EMPTY);
      hk6_offer(&state,large,HK6_FRAME_CAP);assert(state.phase==HK6_READY && state.length==payload);
      assert(!memcmp(slot,large,payload));state.frame=0;state.active=state.want=0;
      free(slot);free(large); }
    done();puts("Stock HTTP core checks passed (13 groups)");
    return 0;
}
