/* Host adapters only: these do not emulate the Beken sensor, RTOS or Wi-Fi. */
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
static int fail_alloc;
static int fragment_recv;
static unsigned frame_reads;
static unsigned frame_mode;
static void *rt_malloc(size_t n) { return fail_alloc ? NULL : malloc(n); }
static void rt_free(void *p) { free(p); }
static void rt_thread_mdelay(int ms) { (void)ms; }
static int lwip_send(int fd, const void *p, size_t n, int flags)
{
    return send(fd, p, n > 7 ? 7 : n, flags); /* exercise partial writes */
}
static int lwip_recv(int fd, void *p, size_t n, int flags)
{
    if (fragment_recv && n > 10) n = 10;
    return recv(fd, p, n, flags);
}
static int video_buffer_open(void) { return 0; }
static uint32_t video_buffer_read_frame(uint8_t *p, uint32_t cap)
{
    const uint8_t frame[] = {0xff, 0xd8, 0xff, 0xd9, 0, 4, 0, 0, 0};
    (void)cap;
    if (frame_mode == 1 || frame_reads++) return 0;
    if (frame_mode == 2) return cap+1;
    memcpy(p, frame, sizeof(frame));
    return sizeof(frame);
}
