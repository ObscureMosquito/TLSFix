#include "tlsfix.h"
#include <dlfcn.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <limits.h>
#include <openssl/err.h>

extern void MSHookFunction(void *symbol, void *replace, void **result);

#define WANT_IO(e) ((e) == SSL_ERROR_WANT_READ || (e) == SSL_ERROR_WANT_WRITE)

static int negotiated(Shadow *s) { return s && (s->state == SH_CONNECTED || s->state == SH_PAUSED); }
static int cipher_chosen(Shadow *s) { return s->ssl && SSL_get_current_cipher(s->ssl); }
static int failed(Shadow *s) { return s && s->aborted && s->state != SH_CONNECTED && !s->passThrough; }

static OSStatus (*o_SetIOFuncs)(SSLContextRef, SSLReadFunc, SSLWriteFunc);
static OSStatus my_SetIOFuncs(SSLContextRef c, SSLReadFunc rf, SSLWriteFunc wf) {
    if (ensure_ready() != 1) return o_SetIOFuncs(c, rf, wf);
    OSStatus r = o_SetIOFuncs(c, rf, wf);
    Shadow *s = sh_create(c);
    if (s) { s->rf = rf; s->wf = wf; sh_release(s); }
    return r;
}
static OSStatus (*o_SetConnection)(SSLContextRef, SSLConnectionRef);
static OSStatus my_SetConnection(SSLContextRef c, SSLConnectionRef conn) {
    if (ensure_ready() != 1) return o_SetConnection(c, conn);
    OSStatus r = o_SetConnection(c, conn);
    Shadow *s = sh_create(c);
    if (s) { s->conn = conn; sh_release(s); }
    return r;
}
static OSStatus (*o_SetPeerDomainName)(SSLContextRef, const char *, size_t);
static OSStatus my_SetPeerDomainName(SSLContextRef c, const char *name, size_t len) {
    if (ensure_ready() != 1) return o_SetPeerDomainName(c, name, len);
    OSStatus r = o_SetPeerDomainName(c, name, len);
    Shadow *s = sh_create(c);
    if (s) {
        if (name && len) {
            size_t n = len < 255 ? len : 255; memcpy(s->host, name, n); s->host[n] = 0;
            if (s->inited && s->state != SH_FAILED) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = SH_IDLE; } // late SNI -> re-init
        }
        sh_release(s);
    }
    return r;
}
static OSStatus (*o_SetSessionOption)(SSLContextRef, SSLSessionOption, Boolean);
static OSStatus my_SetSessionOption(SSLContextRef c, SSLSessionOption opt, Boolean val) {
    int certReq = opt == kSSLSessionOptionBreakOnCertRequested && !OS_BEFORE_IOS5;
    if (ensure_ready() == 1 && (opt == kSSLSessionOptionBreakOnServerAuth || certReq)) {
        Shadow *s = sh_create(c);
        if (s) { if (certReq) s->breakCertReq = val ? 1 : 0; else s->breakAuth = val ? 1 : 0; sh_release(s); }
    }
    return o_SetSessionOption(c, opt, val);
}

static OSStatus (*o_Handshake)(SSLContextRef);
static OSStatus handshake_step(Shadow *s, int *system) {
    if (!s->rf || !s->wf || !s->conn || s->clientBypass || s->passThrough || (s->state == SH_FAILED && !s->aborted)) { *system = 1; return noErr; }
    if (s->aborted) return ST_ClosedAbort;
    if (!s->inited) {
        if (ossl_init(s)) { s->state = SH_FAILED; *system = 1; return noErr; }
        s->state = SH_HANDSHAKE;
    }
    if (s->state == SH_PAUSED) s->approved = 1;
    ERR_clear_error();
    int ret = SSL_do_handshake(s->ssl);
    if (ret == 1) {
        if (s->breakAuth && !s->approved) { s->state = SH_PAUSED; return ST_PeerAuth; }
        s->state = SH_CONNECTED;
        return noErr;
    }
    int e = SSL_get_error(s->ssl, ret);
    if (e == SSL_ERROR_WANT_X509_LOOKUP) {
        int why = s->pause;
        s->pause = PAUSE_NONE;
        if (why == PAUSE_AUTH) { s->state = SH_PAUSED; return ST_PeerAuth; }
        if (why == PAUSE_CERTREQ) { s->certReqAnswered = 1; return errSSLClientCertRequested; }
        return sh_abort_handshake(s);
    }
    if (WANT_IO(e)) return errSSLWouldBlock;
    return sh_fail_handshake(s, e);
}
static OSStatus my_Handshake(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (!s) return o_Handshake(c);
    int system = 0;
    OSStatus rv = handshake_step(s, &system);
    if (system) rv = o_Handshake(c);
    sh_release(s);
    return rv;
}

static OSStatus flush_wbuf(Shadow *s) {
    while (s->woff < s->wlen) {
        size_t left = s->wlen - s->woff; if (left > (size_t)INT_MAX) left = (size_t)INT_MAX;
        ERR_clear_error();
        int n = SSL_write(s->ssl, s->wbuf + s->woff, (int)left);
        if (n > 0) { s->woff += (size_t)n; continue; }
        if (WANT_IO(SSL_get_error(s->ssl, n))) return errSSLWouldBlock;
        sh_abort(s);
        return ST_ClosedAbort;
    }
    if (s->wbuf) { free(s->wbuf); s->wbuf = NULL; s->wlen = s->woff = 0; }
    return noErr;
}

static OSStatus (*o_Read)(SSLContextRef, void *, size_t, size_t *);
static OSStatus my_Read(SSLContextRef c, void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (failed(s)) { *processed = 0; sh_release(s); return ST_ClosedAbort; }
    if (!s || s->state != SH_CONNECTED) { OSStatus r = o_Read(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    OSStatus fr = flush_wbuf(s);
    if (fr != noErr && fr != errSSLWouldBlock) { sh_release(s); return fr; }
    ERR_clear_error();
    int n = SSL_read(s->ssl, data, (int)len);
    OSStatus rv = noErr;
    if (n > 0) *processed = (size_t)n;
    else {
        int e = SSL_get_error(s->ssl, n);
        if (WANT_IO(e)) rv = errSSLWouldBlock;
        else if (e == SSL_ERROR_ZERO_RETURN) { s->closed = 1; rv = ST_ClosedGraceful; }
        else rv = sh_fail_read(s, e);
    }
    sh_release(s);
    return rv;
}

// like SSLWrite: accept the whole buffer, report errSSLWouldBlock with processed = len and send the rest on the next call
static OSStatus write_data(Shadow *s, const void *data, size_t len, size_t *processed) {
    size_t done = 0;
    OSStatus rv = noErr;
    while (done < len) {
        size_t chunk = len - done; if (chunk > (size_t)INT_MAX) chunk = (size_t)INT_MAX;
        ERR_clear_error();
        int n = SSL_write(s->ssl, (const char *)data + done, (int)chunk);
        if (n > 0) { done += (size_t)n; continue; }
        if (WANT_IO(SSL_get_error(s->ssl, n))) {
            s->wbuf = (unsigned char *)malloc(len - done);
            if (s->wbuf) { memcpy(s->wbuf, (const char *)data + done, len - done); s->wlen = len - done; s->woff = 0; done = len; }
            rv = errSSLWouldBlock;
        } else { sh_abort(s); rv = ST_ClosedAbort; }
        break;
    }
    *processed = done;
    return rv;
}
static OSStatus (*o_Write)(SSLContextRef, const void *, size_t, size_t *);
static OSStatus my_Write(SSLContextRef c, const void *data, size_t len, size_t *processed) {
    Shadow *s = sh_get(c);
    if (failed(s)) { *processed = 0; sh_release(s); return ST_ClosedAbort; }
    if (!s || s->state != SH_CONNECTED) { OSStatus r = o_Write(c, data, len, processed); sh_release(s); return r; }
    *processed = 0;
    OSStatus rv = flush_wbuf(s);
    if (rv == noErr) rv = write_data(s, data, len, processed);
    sh_release(s);
    return rv;
}

static OSStatus (*o_Close)(SSLContextRef);
static OSStatus my_Close(SSLContextRef c) {
    Shadow *s = sh_get(c);
    if (s && s->state == SH_CONNECTED && s->ssl && !s->aborted) {
        flush_wbuf(s);
        ERR_clear_error();
        if (!s->aborted) SSL_shutdown(s->ssl);   // not after a fatal error
    }
    sh_release(s);
    OSStatus r = o_Close(c);
    sh_free(c);
    return r;
}

static OSStatus (*o_GetSessionState)(SSLContextRef, SSLSessionState *);
static OSStatus my_GetSessionState(SSLContextRef c, SSLSessionState *st) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    if (s && !s->passThrough && s->aborted) { if (st) *st = s->failState; }
    else if (s && !s->passThrough && s->closed) { if (st) *st = kSSLClosed; }
    else if (s && s->state > SH_IDLE) { if (st) *st = s->state == SH_CONNECTED ? kSSLConnected : kSSLHandshake; }
    else rv = o_GetSessionState(c, st);
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetNegProto)(SSLContextRef, SSLProtocol *);
static OSStatus my_GetNegProto(SSLContextRef c, SSLProtocol *p) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    if (negotiated(s) || (s && s->state == SH_HANDSHAKE && cipher_chosen(s))) { if (p) *p = kTLSProtocol1; }
    else rv = o_GetNegProto(c, p);
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetNegCipher)(SSLContextRef, UInt32 *);
static OSStatus my_GetNegCipher(SSLContextRef c, UInt32 *cipher) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    if (negotiated(s)) { if (cipher) *cipher = TLS_RSA_WITH_AES_128_CBC_SHA; }
    else if (s && s->state == SH_HANDSHAKE) { if (cipher) *cipher = cipher_chosen(s) ? TLS_RSA_WITH_AES_128_CBC_SHA : 0; }
    else rv = o_GetNegCipher(c, cipher);
    sh_release(s);
    return rv;
}
static OSStatus (*o_GetBuffered)(SSLContextRef, size_t *);
static OSStatus my_GetBuffered(SSLContextRef c, size_t *sz) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    if (s && s->state == SH_CONNECTED) { if (sz) *sz = (size_t)SSL_pending(s->ssl); }
    else rv = o_GetBuffered(c, sz);
    sh_release(s);
    return rv;
}
static OSStatus (*o_CopyPeerTrust)(SSLContextRef, SecTrustRef *);
static OSStatus my_CopyPeerTrust(SSLContextRef c, SecTrustRef *trust) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    if (!negotiated(s) || !trust || !sh_build_trust(s, trust)) rv = o_CopyPeerTrust(c, trust);
    sh_release(s);
    return rv;
}
static OSStatus (*o_CopyPeerCerts)(SSLContextRef, CFArrayRef *);
static OSStatus my_CopyPeerCerts(SSLContextRef c, CFArrayRef *certs) {
    Shadow *s = sh_get(c);
    OSStatus rv = noErr;
    CFArrayRef arr = (negotiated(s) && certs) ? sh_cert_array(s) : NULL;
    if (arr) *certs = arr; else rv = o_CopyPeerCerts(c, certs);
    sh_release(s);
    return rv;
}
static OSStatus (*o_SetCertificate)(SSLContextRef, CFArrayRef);
static OSStatus my_SetCertificate(SSLContextRef c, CFArrayRef certRefs) {
    if (ensure_ready() != 1) return o_SetCertificate(c, certRefs);
    Shadow *s = sh_create(c);
    if (s) {
        if (!s->passThrough) {
            if (!s->certReqAnswered && s->inited && s->state != SH_FAILED) { SSL_free(s->ssl); s->ssl = NULL; s->inited = 0; s->state = SH_IDLE; }
            capture_identity(s, certRefs);
            if (s->certReqAnswered) s->clientBypass = 0;
        }
        sh_release(s);
    }
    return o_SetCertificate(c, certRefs);
}

static void note_new_context(SSLContextRef c, int server, int datagram) {
    if (!c || ensure_ready() != 1) return;
    sh_free(c);
    if (server || datagram) {
        Shadow *s = sh_create(c);
        if (s) { s->passThrough = 1; sh_release(s); }
    }
}
static SSLContextRef (*o_CreateContext)(CFAllocatorRef, SSLProtocolSide, SSLConnectionType);
static SSLContextRef my_CreateContext(CFAllocatorRef a, SSLProtocolSide side, SSLConnectionType type) {
    SSLContextRef c = o_CreateContext(a, side, type);
    note_new_context(c, side == kSSLServerSide, type == kSSLDatagramType);
    return c;
}
static OSStatus (*o_NewContext)(Boolean, SSLContextRef *);
static OSStatus my_NewContext(Boolean isServer, SSLContextRef *out) {
    OSStatus r = o_NewContext(isServer, out);
    if (r == noErr && out) note_new_context(*out, isServer, 0);
    return r;
}

static OSStatus (*o_SetEnableCertVerify)(SSLContextRef, Boolean);
static OSStatus my_SetEnableCertVerify(SSLContextRef c, Boolean on) {
    if (ensure_ready() == 1) {
        Shadow *s = sh_create(c);
        if (s) { s->noVerify = !on; sh_release(s); }
    }
    return o_SetEnableCertVerify(c, on);
}
static OSStatus (*o_SetAllowsAnyRoot)(SSLContextRef, Boolean);
static OSStatus my_SetAllowsAnyRoot(SSLContextRef c, Boolean on) {
    if (ensure_ready() == 1) {
        Shadow *s = sh_create(c);
        if (s) { s->anyRoot = on; sh_release(s); }
    }
    return o_SetAllowsAnyRoot(c, on);
}

static OSStatus my_TrustEvaluate(SecTrustRef t, SecTrustResultType *result) {
    OSStatus rv = o_TrustEvaluate(t, result);

    if (rv != errSecSuccess || !result) return rv;

    int trusted = *result == kSecTrustResultProceed || *result == kSecTrustResultUnspecified;

    if (!trusted && sh_trust_verified(t)) {
        *result = kSecTrustResultUnspecified;
    }

    return rv;
}

static OSStatus (*o_SetAnchors)(SecTrustRef, CFArrayRef);
static OSStatus my_SetAnchors(SecTrustRef t, CFArrayRef anchors) {
    sh_forget_trust(t);
    return o_SetAnchors(t, anchors);
}

static OSStatus (*o_SetAnchorsOnly)(SecTrustRef, Boolean);
static OSStatus my_SetAnchorsOnly(SecTrustRef t, Boolean only) {
    sh_forget_trust(t);
    return o_SetAnchorsOnly(t, only);
}

static OSStatus (*o_SetPolicies)(SecTrustRef, CFTypeRef);
static OSStatus my_SetPolicies(SecTrustRef t, CFTypeRef policies) {
    sh_forget_trust(t);
    return o_SetPolicies(t, policies);
}

typedef struct {
    const unsigned char *bytes;
    const unsigned char *mask;
    unsigned             len;
    unsigned             skip;
    int                  entryOnMismatch;
} Prologue;

// cbnz-guarded prologue (iPhoneOS 3 - 4, MobileSubstrate 0.9.5101 cannot relocate it): hook behind the null check
static const Prologue kNullCheck = { (const unsigned char *)"\x08\xb9\x32\x38\x00\xe0", (const unsigned char *)"\xff\xff\xff\xff\x00\xff", 6, 6, 1 };
// private setters CFNetwork calls on iOS 5 - 6: hooked only on exactly these bytes
static const Prologue kEnableCertVerify = { (const unsigned char *)"\x6f\xf0\x31\x02\x40\xb1\xd0\xf8\x48\x32\x6f\xf4\x63\x72", NULL, 14, 6, 0 };
static const Prologue kAllowsAnyRoot = { (const unsigned char *)"\x02\x46\x6f\xf0\x31\x00\x00\x2a", NULL, 8, 0, 0 };

static int prologue_matches(const unsigned char *p, const Prologue *at) {
    for (unsigned i = 0; i < at->len; i++)
        if ((p[i] ^ at->bytes[i]) & (at->mask ? at->mask[i] : 0xff)) return 0;
    return 1;
}

static void hook(const char *name, const Prologue *at, void *repl, void **orig) {
    void *sym = dlsym(RTLD_DEFAULT, name);
    if (!sym) return;
    if (at) {
        const unsigned char *p = (const unsigned char *)((uintptr_t)sym & ~(uintptr_t)1);
        if (((uintptr_t)sym & 1) && prologue_matches(p, at)) sym = (void *)((uintptr_t)p + at->skip + 1);   // +1 keeps Thumb state
        else if (!at->entryOnMismatch) return;
    }
    MSHookFunction(sym, repl, orig);
}
#define HOOK(name, at, fn) hook(name, at, (void *)my_##fn, (void **)&o_##fn)

static void install_common(void) {
    HOOK("SSLSetIOFuncs",                   NULL, SetIOFuncs);
    HOOK("SSLSetConnection",                NULL, SetConnection);
    HOOK("SSLSetPeerDomainName",            NULL, SetPeerDomainName);
    HOOK("SSLSetSessionOption",             NULL, SetSessionOption);
    HOOK("SSLHandshake",                    NULL, Handshake);
    HOOK("SSLRead",                         NULL, Read);
    HOOK("SSLWrite",                        NULL, Write);
    HOOK("SSLClose",                        NULL, Close);
    HOOK("SSLGetSessionState",              &kNullCheck, GetSessionState);
    HOOK("SSLGetNegotiatedProtocolVersion", &kNullCheck, GetNegProto);
    HOOK("SSLGetNegotiatedCipher",          NULL, GetNegCipher);
    HOOK("SSLGetBufferedReadSize",          &kNullCheck, GetBuffered);
    HOOK("SSLCopyPeerTrust",                NULL, CopyPeerTrust);
    if (!dlsym(RTLD_DEFAULT, "_SSLCopyPeerCertificates"))
        HOOK("SSLCopyPeerCertificates",     NULL, CopyPeerCerts);
    HOOK("SSLSetCertificate",               NULL, SetCertificate);
    HOOK("SSLCreateContext",                NULL, CreateContext);
}

static void install_before_ios5(void) {
    tlsfix_ecc_fallback = 1;
    HOOK("SSLNewContext",                     NULL, NewContext);
    HOOK("SSLSetEnableCertVerify",            NULL, SetEnableCertVerify);
    HOOK("SecTrustSetAnchorCertificates",     NULL, SetAnchors);
    HOOK("SecTrustSetAnchorCertificatesOnly", NULL, SetAnchorsOnly);
    HOOK("SecTrustSetPolicies",               NULL, SetPolicies);
    HOOK("SecTrustEvaluate",                  NULL, TrustEvaluate);
}

static void install_ios5_ios6(void) {
    HOOK("_SSLSetEnableCertVerify", &kEnableCertVerify, SetEnableCertVerify);
    HOOK("_SSLSetAllowsAnyRoot",    &kAllowsAnyRoot,    SetAllowsAnyRoot);
}

__attribute__((constructor))
static void tlsfix_init(void) {
    const char *pn = getprogname();

    static const char *deny[] = { "SpringBoard", "backboardd", "launchd", "assertiond", "lockdownd",
                                  "securityd", "trustd", 0 };

    for (int i = 0; deny[i]; i++) if (pn && !strcmp(pn, deny[i])) return;
    install_common();
    if (OS_BEFORE_IOS5) install_before_ios5();
    else if (OS_BEFORE_IOS7) install_ios5_ios6();
}
