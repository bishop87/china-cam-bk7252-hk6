#define LOCALCAM_HOST_TEST
#include "../firmware/localcam/localcam.c"
#include <assert.h>

static size_t request(const char *req, char *out, size_t cap)
{
    int fd[2];
    size_t used = 0;
    ssize_t n;
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == 0);
    assert(write(fd[0], req, strlen(req)) == (ssize_t)strlen(req));
    shutdown(fd[0], SHUT_WR);
    serve_client(fd[1]);
    shutdown(fd[1], SHUT_WR);
    while ((n = read(fd[0], out+used, cap-1-used)) > 0) used += n;
    out[used] = 0;
    close(fd[0]); close(fd[1]);
    return used;
}

int main(void)
{
    char out[4096], large[1500];
    size_t n;
    fragment_recv = 1;
    request("GET / HTTP/1.1\r\nHost: localcam\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "200 OK") && strstr(out, "src=/stream.mjpg"));
    fragment_recv = 0;
    request("GET /other HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "404 Not Found"));
    frame_reads = 0;
    n = request("GET /snapshot.jpg HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "Content-Length: 4\r\n"));
    assert(!memcmp(out+n-4, "\xff\xd8\xff\xd9", 4));
    frame_reads = 0;
    request("GET /stream.mjpg HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "multipart/x-mixed-replace") && strstr(out, "--localcam\r\n"));
    frame_mode = 1;
    request("GET /snapshot.jpg HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "503 Service Unavailable"));
    frame_mode = 2; frame_reads = 0;
    request("GET /snapshot.jpg HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "503 Service Unavailable"));
    fail_alloc = 1;
    request("GET /snapshot.jpg HTTP/1.1\r\n\r\n", out, sizeof(out));
    assert(strstr(out, "Insufficient frame memory"));
    memset(large, 'x', sizeof(large)-1); large[sizeof(large)-1] = 0;
    request(large, out, sizeof(out));
    assert(strstr(out, "431 Request Header Fields Too Large"));
    puts("HTTP host checks passed: fragmented reads, partial writes, routes, JPEG trailer, stream, errors, limits.");
    return 0;
}
