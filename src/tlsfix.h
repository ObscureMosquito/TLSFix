#ifndef TLSFIX_H
#define TLSFIX_H

#include <Security/SecureTransport.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <openssl/ssl.h>

// Secure Transport result codes
#ifndef errSSLWouldBlock
#define errSSLWouldBlock  -9803
#endif

#define ST_ClosedGraceful -9805
#define ST_ClosedAbort    -9806
#define ST_PeerAuth       -9841
#define ST_TLS12           8

#define OS_BEFORE_IOS5  (kCFCoreFoundationVersionNumber < 675.0)
#define OS_BEFORE_IOS7  (kCFCoreFoundationVersionNumber < 800.0)
#define OS_IOS8_PLUS    (kCFCoreFoundationVersionNumber >= 1100.0)

enum { SH_FAILED = -1, SH_IDLE, SH_HANDSHAKE, SH_CONNECTED, SH_PAUSED };
enum { PAUSE_NONE, PAUSE_AUTH, PAUSE_CERTREQ };

typedef struct {
    SSLContextRef    ctx;
    SSLReadFunc      rf;
    SSLWriteFunc     wf;
    SSLConnectionRef conn;
    char             host[256];
    SSL             *ssl;
    int              inited;
    int              state;
    int              pause;
    int              refcount;
    unsigned         lastUse;
    int              breakAuth;
    int              breakCertReq;
    int              approved;
    int              certReqAnswered;
    int              noVerify;
    int              anyRoot;
    int              passThrough;
    int              clientBypass;
    int              aborted;
    int              closed;
    SSLSessionState  failState;
    OSStatus         rdStatus;
    unsigned char   *wbuf;
    size_t           wlen, woff;
    X509            *clientX509;
    STACK_OF(X509)  *clientChain;
    SecKeyRef        clientKey;
    SecTrustRef      eccTrust;
} Shadow;

int ensure_ready(void);
Shadow *sh_get(SSLContextRef c);
Shadow *sh_create(SSLContextRef c);
void sh_release(Shadow *s);
void sh_free(SSLContextRef c);
int ossl_init(Shadow *s);
void capture_identity(Shadow *s, CFArrayRef certRefs);
int sh_build_trust(Shadow *s, SecTrustRef *trust);
CFArrayRef sh_cert_array(Shadow *s);
int sh_trust_verified(SecTrustRef t);
void sh_forget_trust(SecTrustRef t);

void sh_abort(Shadow *s);
OSStatus sh_abort_handshake(Shadow *s);
OSStatus sh_fail_handshake(Shadow *s, int sslError);
OSStatus sh_fail_read(Shadow *s, int sslError);

extern int tlsfix_ecc_fallback;
extern OSStatus (*o_TrustEvaluate)(SecTrustRef, SecTrustResultType *);
int ecc_in_chain(STACK_OF(X509) *chain);
int ecc_verify(STACK_OF(X509) *chain, const char *host);

#endif
