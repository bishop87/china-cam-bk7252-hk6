#ifndef HK6_HTTP_H
#define HK6_HTTP_H
#include <stdint.h>
#include <stddef.h>
#define HK6_FRAME_CAP 40928u
#define HK6_REQUEST_CAP 1024u
enum hk6_phase { HK6_EMPTY, HK6_COPYING, HK6_READY, HK6_SENDING };
struct hk6_state {
    volatile uint32_t active, want, phase;
    uint8_t *frame;
    uint32_t length, delivered, dropped;
};
/* Platform boundary: stock ABI on ARM, deterministic adapters in host tests. */
uint32_t hk6_lock(void);
void hk6_unlock(uint32_t key);
uint32_t hk6_now(void);
void hk6_delay(uint32_t ms);
void *hk6_alloc(uint32_t bytes);
void hk6_free(void *p);
struct hk6_state *hk6_lookup(void);
int hk6_send(int fd, const void *p, uint32_t n);
int hk6_recv(int fd, void *p, uint32_t n);
int hk6_timeouts(int fd);
void hk6_offer(struct hk6_state *s, const uint8_t *frame, uint32_t n);
int hk6_needed(void);
void hk6_serve(struct hk6_state *s, int fd);
void hk6_boot(void);
uint32_t hk6_read(uint8_t *p, uint32_t capacity);
#endif
