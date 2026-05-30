/*
Copyright 2026 masqr contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

/*
 * masqr LD_PRELOAD resolver shim.
 *
 * Interposes getaddrinfo(3): when the looked-up host equals
 * $MASQR_REDIRECT_HOST, resolve $MASQR_REDIRECT_IP (default 127.0.0.1)
 * instead, so a child whose API client dials a hardcoded hostname lands on
 * masqr's local TLS listener. Every other lookup is delegated untouched to
 * the real libc getaddrinfo via dlsym(RTLD_NEXT, ...).
 *
 * This is the no-sudo redirect mechanism for `masqr agy`: masqr sets
 * LD_PRELOAD=<this .so>, GODEBUG=netdns=cgo (so the Go child resolves through
 * libc getaddrinfo rather than its built-in resolver), and the two
 * MASQR_REDIRECT_* vars, all scoped to the child process tree. Nothing global
 * changes and there is nothing to tear down.
 *
 * Built at runtime by masqr (cc -shared -fPIC -ldl); the C source is embedded
 * into the masqr binary, so no build-time toolchain or per-arch .so is needed.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>

typedef int (*gai_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    static gai_t real;
    if (!real) {
        real = (gai_t)dlsym(RTLD_NEXT, "getaddrinfo");
        if (!real) return EAI_SYSTEM;
    }
    const char *target = getenv("MASQR_REDIRECT_HOST");
    if (node && target && *target && strcmp(node, target) == 0) {
        const char *to = getenv("MASQR_REDIRECT_IP");
        if (!to || !*to) to = "127.0.0.1";
        return real(to, service, hints, res);
    }
    return real(node, service, hints, res);
}
