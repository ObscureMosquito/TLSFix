#include "tlsfix.h"
#include <openssl/err.h>
#include <openssl/x509_vfy.h>

static const struct { int alert; OSStatus status; } kPeerAlert[] = {
    { SSL3_AD_UNEXPECTED_MESSAGE,       errSSLPeerUnexpectedMsg },
    { SSL3_AD_BAD_RECORD_MAC,           errSSLPeerBadRecordMac },
    { TLS1_AD_DECRYPTION_FAILED,        errSSLPeerDecryptionFail },
    { TLS1_AD_RECORD_OVERFLOW,          errSSLPeerRecordOverflow },
    { SSL3_AD_DECOMPRESSION_FAILURE,    errSSLPeerDecompressFail },
    { SSL3_AD_HANDSHAKE_FAILURE,        errSSLPeerHandshakeFail },
    { SSL3_AD_BAD_CERTIFICATE,          errSSLPeerBadCert },
    { SSL3_AD_UNSUPPORTED_CERTIFICATE,  errSSLPeerUnsupportedCert },
    { SSL3_AD_CERTIFICATE_REVOKED,      errSSLPeerCertRevoked },
    { SSL3_AD_CERTIFICATE_EXPIRED,      errSSLPeerCertExpired },
    { SSL3_AD_CERTIFICATE_UNKNOWN,      errSSLPeerCertUnknown },
    { SSL3_AD_ILLEGAL_PARAMETER,        errSSLIllegalParam },
    { TLS1_AD_UNKNOWN_CA,               errSSLPeerUnknownCA },
    { TLS1_AD_ACCESS_DENIED,            errSSLPeerAccessDenied },
    { TLS1_AD_DECODE_ERROR,             errSSLPeerDecodeError },
    { TLS1_AD_DECRYPT_ERROR,            errSSLPeerDecryptError },
    { TLS1_AD_EXPORT_RESTRICTION,       errSSLPeerExportRestriction },
    { TLS1_AD_PROTOCOL_VERSION,         errSSLPeerProtocolVersion },
    { TLS1_AD_INSUFFICIENT_SECURITY,    errSSLPeerInsufficientSecurity },
    { TLS1_AD_INTERNAL_ERROR,           errSSLPeerInternalError },
    { TLS1_AD_USER_CANCELLED,           errSSLPeerUserCancelled },
    { TLS1_AD_NO_RENEGOTIATION,         errSSLPeerNoRenegotiation },
};

static OSStatus peer_alert(Shadow *s, int alert, SSLSessionState *state) {
    *state = kSSLHandshake;
    if (alert == SSL3_AD_CLOSE_NOTIFY) { *state = kSSLClosed; return ST_ClosedGraceful; }
    if (alert == SSL3_AD_NO_CERTIFICATE) { *state = kSSLAborted; return OS_BEFORE_IOS5 ? errSSLConnectionRefused : ST_ClosedAbort; }
    if (alert == TLS1_AD_PROTOCOL_VERSION && SSL_get_min_proto_version(s->ssl) > TLS1_VERSION) { *state = kSSLAborted; return errSSLNegotiation; }
    for (size_t i = 0; i < sizeof kPeerAlert / sizeof kPeerAlert[0]; i++)
        if (kPeerAlert[i].alert == alert) return kPeerAlert[i].status;
    return errSSLFatalAlert;
}

static OSStatus classify(Shadow *s, int handshake) {
    unsigned long err = ERR_peek_last_error();
    int reason = ERR_GET_LIB(err) == ERR_LIB_SSL ? ERR_GET_REASON(err) : 0;
    OSStatus rv = ST_ClosedAbort;
    if (SSL_get_verify_result(s->ssl) != X509_V_OK || reason == SSL_R_CERTIFICATE_VERIFY_FAILED)
        rv = errSSLXCertChainInvalid;
    else if (reason >= SSL_AD_REASON_OFFSET && reason < SSL_AD_REASON_OFFSET + 256) {
        SSLSessionState state;
        rv = peer_alert(s, reason - SSL_AD_REASON_OFFSET, &state);
        if (handshake) s->failState = state;
    }
    else if (reason == SSL_R_UNSUPPORTED_PROTOCOL || reason == SSL_R_NO_PROTOCOLS_AVAILABLE)
        rv = errSSLNegotiation;
    else if (handshake && reason) {
        rv = errSSLProtocol;
        if (OS_BEFORE_IOS5) s->failState = kSSLHandshake;
    }
    else if (handshake && OS_BEFORE_IOS5 && s->rdStatus == ST_ClosedGraceful) {
        rv = errSSLConnectionRefused;
        s->failState = kSSLAborted;
    }
    ERR_clear_error();
    return rv;
}

void sh_abort(Shadow *s) {
    s->aborted = 1;
    s->failState = kSSLAborted;
}

OSStatus sh_abort_handshake(Shadow *s) {
    s->state = SH_FAILED;
    sh_abort(s);
    return ST_ClosedAbort;
}

OSStatus sh_fail_handshake(Shadow *s, int sslError) {
    s->state = SH_FAILED;
    sh_abort(s);
    if (sslError == SSL_ERROR_ZERO_RETURN) {
        s->failState = kSSLClosed;
        ERR_clear_error();
        return ST_ClosedGraceful;
    }
    return classify(s, 1);
}

OSStatus sh_fail_read(Shadow *s, int sslError) {
    sh_abort(s);
    if (sslError == SSL_ERROR_SYSCALL && s->rdStatus == ST_ClosedGraceful) {
        ERR_clear_error();
        return OS_BEFORE_IOS5 ? errSSLClosedNoNotify : ST_ClosedGraceful;
    }
    return classify(s, 0);
}
