/*
 * A Windows program that does what a game's network code does: open a Winsock TCP socket,
 * connect, send a request, read the answer. Under Wine the socket is created inside the
 * prefix's wineserver, not in this program, which is what a routing rule has to account for.
 *
 *   x86_64-w64-mingw32-gcc -O2 -o winsock_probe.exe winsock_probe.c -lws2_32
 *   wine winsock_probe.exe <ipv4> <port> [attempts] [interval-ms]
 *
 * Prints one line per attempt: "ok <first line of the body>", or "fail <WSA error>".
 */
#include <winsock2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc < 3)
    {
        fprintf(stderr, "usage: winsock_probe <ipv4> <port> [attempts] [interval-ms]\n");
        return 2;
    }

    int attempts = argc > 3 ? atoi(argv[3]) : 1;
    int interval = argc > 4 ? atoi(argv[4]) : 500;

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        fprintf(stderr, "WSAStartup failed\n");
        return 1;
    }

    struct sockaddr_in target;
    memset(&target, 0, sizeof target);
    target.sin_family = AF_INET;
    target.sin_port = htons((u_short)atoi(argv[2]));
    target.sin_addr.s_addr = inet_addr(argv[1]);

    for (int i = 0; i < attempts; i++)
    {
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        DWORD timeout = 1500;
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof timeout);
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof timeout);

        /* A blocking connect to a black hole would take the system's whole SYN timeout. */
        u_long nonblocking = 1;
        ioctlsocket(s, FIONBIO, &nonblocking);
        connect(s, (struct sockaddr *)&target, sizeof target);
        fd_set writable;
        FD_ZERO(&writable);
        FD_SET(s, &writable);
        struct timeval wait = { 1, 500000 };
        int ready = select(0, NULL, &writable, NULL, &wait);
        int error = 0;
        int length = sizeof error;
        getsockopt(s, SOL_SOCKET, SO_ERROR, (char *)&error, &length);
        nonblocking = 0;
        ioctlsocket(s, FIONBIO, &nonblocking);

        if (ready == 1 && error == 0)
        {
            const char request[] = "GET / HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n";
            send(s, request, (int)sizeof request - 1, 0);
            char buffer[2048];
            int total = 0;
            int n;
            while (total < (int)sizeof buffer - 1 && (n = recv(s, buffer + total, (int)sizeof buffer - 1 - total, 0)) > 0)
            {
                total += n;
            }
            buffer[total] = '\0';
            const char *body = strstr(buffer, "\r\n\r\n");
            printf("ok %s\n", body ? body + 4 : buffer);
        }
        else
        {
            printf("fail %d\n", ready == 1 ? error : WSAETIMEDOUT);
        }

        fflush(stdout);
        closesocket(s);
        Sleep(interval);
    }

    WSACleanup();
    return 0;
}
