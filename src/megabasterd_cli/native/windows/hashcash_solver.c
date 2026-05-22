#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")

#define TOKEN_BYTES 48
#define REPEAT 262144
#define DIGEST_BYTES 32
#define MAX_WORKERS 32

typedef struct WorkerArgs {
    uint32_t start;
    uint32_t step;
    uint32_t threshold;
    ULONGLONG deadline;
    BCRYPT_ALG_HANDLE alg;
    DWORD hash_object_size;
    const unsigned char *payload;
    DWORD payload_size;
    volatile LONG *stop;
    volatile LONG *found;
    unsigned char *result;
} WorkerArgs;

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t out_len) {
    size_t hex_len = strlen(hex);
    if (hex_len != out_len * 2) return 0;
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex_value(hex[i * 2]);
        int lo = hex_value(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (unsigned char)((hi << 4) | lo);
    }
    return 1;
}

static uint32_t threshold_for(int easiness) {
    unsigned long long base = (unsigned long long)(((easiness & 0x3F) << 1) + 1);
    unsigned int shift = (unsigned int)(((easiness >> 6) * 7) + 3);
    unsigned long long value = base << shift;
    return value > 0xFFFFFFFFull ? 0xFFFFFFFFu : (uint32_t)value;
}

static void print_hex4(const unsigned char *data) {
    static const char alphabet[] = "0123456789abcdef";
    char out[9];
    for (int i = 0; i < 4; ++i) {
        out[i * 2] = alphabet[data[i] >> 4];
        out[i * 2 + 1] = alphabet[data[i] & 0x0F];
    }
    out[8] = '\0';
    puts(out);
}

static DWORD WINAPI worker_main(void *param) {
    WorkerArgs *args = (WorkerArgs *)param;
    unsigned char digest[DIGEST_BYTES];
    unsigned char nonce[4];
    unsigned char *hash_object = (unsigned char *)malloc(args->hash_object_size);
    if (!hash_object) return 1;

    uint32_t candidate = args->start;
    while (InterlockedCompareExchange(args->stop, 0, 0) == 0 && GetTickCount64() < args->deadline) {
        nonce[0] = (unsigned char)(candidate >> 24);
        nonce[1] = (unsigned char)(candidate >> 16);
        nonce[2] = (unsigned char)(candidate >> 8);
        nonce[3] = (unsigned char)candidate;

        BCRYPT_HASH_HANDLE hash = NULL;
        NTSTATUS status = BCryptCreateHash(
            args->alg,
            &hash,
            hash_object,
            args->hash_object_size,
            NULL,
            0,
            0
        );
        if (status < 0) break;
        status = BCryptHashData(hash, nonce, 4, 0);
        if (status >= 0) {
            status = BCryptHashData(hash, (PUCHAR)args->payload, args->payload_size, 0);
        }
        if (status >= 0) {
            status = BCryptFinishHash(hash, digest, DIGEST_BYTES, 0);
        }
        BCryptDestroyHash(hash);
        if (status < 0) break;

        uint32_t head =
            ((uint32_t)digest[0] << 24) |
            ((uint32_t)digest[1] << 16) |
            ((uint32_t)digest[2] << 8) |
            (uint32_t)digest[3];

        if (head <= args->threshold) {
            if (InterlockedCompareExchange(args->found, 1, 0) == 0) {
                memcpy(args->result, nonce, 4);
            }
            InterlockedExchange(args->stop, 1);
            break;
        }
        candidate += args->step;
    }

    free(hash_object);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 5) {
        fprintf(stderr, "usage: %s <easiness> <token_hex> <workers> <timeout_ms>\n", argv[0]);
        return 1;
    }

    int easiness = atoi(argv[1]);
    int workers = atoi(argv[3]);
    int timeout_ms = atoi(argv[4]);
    if (workers < 1) workers = 1;
    if (workers > MAX_WORKERS) workers = MAX_WORKERS;
    if (timeout_ms < 1) timeout_ms = 1;

    unsigned char token[TOKEN_BYTES];
    if (!hex_to_bytes(argv[2], token, TOKEN_BYTES)) {
        fputs("invalid token hex\n", stderr);
        return 1;
    }

    DWORD payload_size = TOKEN_BYTES * REPEAT;
    unsigned char *payload = (unsigned char *)malloc(payload_size);
    if (!payload) {
        fputs("out of memory\n", stderr);
        return 3;
    }
    for (DWORD offset = 0; offset < payload_size; offset += TOKEN_BYTES) {
        memcpy(payload + offset, token, TOKEN_BYTES);
    }

    BCRYPT_ALG_HANDLE alg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (status < 0) {
        free(payload);
        fputs("BCryptOpenAlgorithmProvider failed\n", stderr);
        return 3;
    }

    DWORD object_size = 0;
    DWORD cb_data = 0;
    status = BCryptGetProperty(
        alg,
        BCRYPT_OBJECT_LENGTH,
        (PUCHAR)&object_size,
        sizeof(object_size),
        &cb_data,
        0
    );
    if (status < 0 || object_size == 0) {
        BCryptCloseAlgorithmProvider(alg, 0);
        free(payload);
        fputs("BCryptGetProperty failed\n", stderr);
        return 3;
    }

    volatile LONG stop = 0;
    volatile LONG found = 0;
    unsigned char result[4] = {0};
    HANDLE threads[MAX_WORKERS];
    WorkerArgs args[MAX_WORKERS];
    uint32_t threshold = threshold_for(easiness);
    ULONGLONG deadline = GetTickCount64() + (ULONGLONG)timeout_ms;

    for (int i = 0; i < workers; ++i) {
        args[i].start = (uint32_t)i;
        args[i].step = (uint32_t)workers;
        args[i].threshold = threshold;
        args[i].deadline = deadline;
        args[i].alg = alg;
        args[i].hash_object_size = object_size;
        args[i].payload = payload;
        args[i].payload_size = payload_size;
        args[i].stop = &stop;
        args[i].found = &found;
        args[i].result = result;
        threads[i] = CreateThread(NULL, 0, worker_main, &args[i], 0, NULL);
        if (!threads[i]) {
            InterlockedExchange(&stop, 1);
            workers = i;
            break;
        }
    }

    if (workers > 0) {
        WaitForMultipleObjects((DWORD)workers, threads, TRUE, (DWORD)timeout_ms + 1000);
        InterlockedExchange(&stop, 1);
        for (int i = 0; i < workers; ++i) {
            WaitForSingleObject(threads[i], 1000);
            CloseHandle(threads[i]);
        }
    }

    BCryptCloseAlgorithmProvider(alg, 0);
    free(payload);

    if (InterlockedCompareExchange(&found, 0, 0) == 1) {
        print_hex4(result);
        return 0;
    }
    return 2;
}
