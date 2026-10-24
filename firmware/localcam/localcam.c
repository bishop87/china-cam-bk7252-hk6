/* SPDX-License-Identifier: GPL-2.0-or-later
 * LocalCam experimental application. Network access: HTTP server + Wi-Fi/DHCP.
 * Camera, radio and RTOS implementation are provided by the pinned Beken SDK.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#ifdef LOCALCAM_HOST_TEST
#include "localcam_host.h"
#else
#include <rtthread.h>
#include <rtdevice.h>
#include "lwip/sockets.h"
#include "wlan_dev.h"
#include "video_transfer.h"
#include "localcam_config.h"
#endif

#define FRAME_CAP (48 * 1024)
#define REQUEST_CAP 1024
static int camera_started;

/* lwip_send() can write less than requested, especially on embedded TCP stacks. */
static int send_all(int fd, const void *data, size_t len)
{
    const char *p = data;
    while (len) {
        int sent = lwip_send(fd, p, len, 0);
        if (sent <= 0) return -1;
        p += sent;
        len -= sent;
    }
    return 0;
}

static int response(int fd, const char *status, const char *type,
                    const void *body, size_t size)
{
    char header[256];
    int n = snprintf(header, sizeof(header),
        "HTTP/1.0 %s\r\nContent-Type: %s\r\nContent-Length: %u\r\n"
        "Cache-Control: no-store\r\nConnection: close\r\n\r\n",
        status, type, (unsigned)size);
    if (n < 0 || n >= (int)sizeof(header) || send_all(fd, header, n)) return -1;
    return send_all(fd, body, size);
}

/* The SDK returns JPEG plus a five-byte trailer; reject malformed frames. */
static uint32_t read_jpeg(uint8_t *frame)
{
    uint32_t n = video_buffer_read_frame(frame, FRAME_CAP);
    if (n < 7 || n > FRAME_CAP || frame[0] != 0xff || frame[1] != 0xd8 ||
        frame[n-7] != 0xff || frame[n-6] != 0xd9) return 0;
    return n - 5;
}

static void serve_video(int fd, int streaming)
{
    uint8_t *frame = rt_malloc(FRAME_CAP);
    uint32_t n = 0;
    if (!frame) {
        const char msg[] = "Insufficient frame memory\n";
        response(fd, "503 Service Unavailable", "text/plain", msg, sizeof(msg)-1);
        return;
    }
    if (!camera_started) {
        if (video_buffer_open() != 0) goto unavailable;
        camera_started = 1;
    }
    n = read_jpeg(frame);
    if (!n) goto unavailable;
    if (!streaming) {
        response(fd, "200 OK", "image/jpeg", frame, n);
    } else {
        const char header[] = "HTTP/1.0 200 OK\r\n"
            "Content-Type: multipart/x-mixed-replace; boundary=localcam\r\n"
            "Cache-Control: no-store\r\nConnection: close\r\n\r\n";
        if (send_all(fd, header, sizeof(header)-1)) goto done;
        do {
            char part[128];
            int len = snprintf(part, sizeof(part),
                "--localcam\r\nContent-Type: image/jpeg\r\nContent-Length: %u\r\n\r\n",
                (unsigned)n);
            if (len < 0 || len >= (int)sizeof(part) || send_all(fd, part, len) ||
                send_all(fd, frame, n) || send_all(fd, "\r\n", 2)) break;
            rt_thread_mdelay(100); /* Limit HTTP output to at most ~10 fps. */
            n = read_jpeg(frame);
        } while (n);
    }
    goto done;
unavailable:
    {
        const char msg[] = "No valid camera frame. Check sensor, wiring and UART log.\n";
        response(fd, "503 Service Unavailable", "text/plain", msg, sizeof(msg)-1);
    }
done:
    rt_free(frame);
}

static void serve_client(int fd)
{
    char request[REQUEST_CAP];
    size_t used = 0;
    int reads = 0;
    /* Bounded reads support fragmented headers without an unbounded slow client. */
    do {
        int n = lwip_recv(fd, request + used, sizeof(request)-1-used, 0);
        if (n <= 0) return;
        used += n;
        request[used] = 0;
        if (strstr(request, "\r\n\r\n")) break;
    } while (used < sizeof(request)-1 && ++reads < 8);
    if (!strstr(request, "\r\n\r\n")) {
        response(fd, "431 Request Header Fields Too Large", "text/plain", "", 0);
        return;
    }
    if (!strncmp(request, "GET / HTTP/1.", 13)) {
        const char page[] = "<!doctype html><html><meta name=viewport content=\"width=device-width\">"
            "<title>LocalCam</title><h1>LocalCam</h1><p>Experimental local camera</p>"
            "<p><a href=/snapshot.jpg>Snapshot JPEG</a></p>"
            "<img src=/stream.mjpg style=\"max-width:100%\" alt=\"Camera stream\"></html>";
        response(fd, "200 OK", "text/html; charset=utf-8", page, sizeof(page)-1);
    } else if (!strncmp(request, "GET /stream.mjpg HTTP/1.", 24)) {
        serve_video(fd, 1);
    } else if (!strncmp(request, "GET /snapshot.jpg HTTP/1.", 25)) {
        serve_video(fd, 0);
    } else {
        response(fd, "404 Not Found", "text/plain", "Not found\n", 10);
    }
}

#ifndef LOCALCAM_HOST_TEST
static void server(void *unused)
{
    struct rt_wlan_device *wlan;
    struct rt_wlan_info info = {0};
    struct sockaddr_in address;
    int listener, result;
    (void)unused;
    rt_thread_mdelay(1500);
#if LOCALCAM_MODE_AP
    wlan = (struct rt_wlan_device *)rt_device_find(WIFI_DEVICE_AP_NAME);
    if (!wlan || rt_wlan_init(wlan, WIFI_AP)) goto wifi_failed;
    rt_wlan_info_init(&info, WIFI_AP, SECURITY_WPA2_AES_PSK, LOCALCAM_SSID);
    info.channel = 6;
    result = rt_wlan_softap(wlan, &info, LOCALCAM_PASSWORD);
#else
    wlan = (struct rt_wlan_device *)rt_device_find(WIFI_DEVICE_STA_NAME);
    if (!wlan || rt_wlan_init(wlan, WIFI_STATION)) goto wifi_failed;
    rt_wlan_info_init(&info, WIFI_STATION, SECURITY_WPA2_MIXED_PSK, LOCALCAM_SSID);
    result = rt_wlan_connect(wlan, &info, LOCALCAM_PASSWORD);
#endif
    rt_wlan_info_deinit(&info);
    if (result) goto wifi_failed;
    listener = lwip_socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(80);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (lwip_bind(listener, (struct sockaddr *)&address, sizeof(address)) < 0 || lwip_listen(listener, 2) < 0) {
        lwip_close(listener);
        rt_kprintf("LocalCam: HTTP listener failed\n");
        return;
    }
    rt_kprintf("LocalCam: HTTP port 80; one video client. AP IP: " DHCPD_SERVER_IP "\n");
    for (;;) {
        int fd = lwip_accept(listener, RT_NULL, RT_NULL);
        struct timeval timeout = {3, 0};
        if (fd < 0) { rt_thread_mdelay(100); continue; }
        if (!lwip_setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) &&
            !lwip_setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) serve_client(fd);
        lwip_close(fd);
    }
wifi_failed:
    rt_kprintf("LocalCam: Wi-Fi initialization failed\n");
}

void app_start(void)
{
    rt_thread_t thread = rt_thread_create("localcam", server, RT_NULL, 4096, 20, 10);
    rt_kprintf("LocalCam 0.1 EXPERIMENTAL: board compatibility unverified\n");
    if (thread) rt_thread_startup(thread);
    else rt_kprintf("LocalCam: thread allocation failed\n");
}
#endif
