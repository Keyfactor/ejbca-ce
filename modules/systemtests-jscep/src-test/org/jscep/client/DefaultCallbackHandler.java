package org.jscep.client;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jscep.client.verification.CertificateVerifier;

/**
 * Class that handles a CertificateVerificationCallback.
 */
public final class DefaultCallbackHandler implements CallbackHandler {
    /**
     * The verifier.
     */
    private final CertificateVerifier verifier;

    /**
     * Default callback handler that delegates verification to a verifier.
     * 
     * @param verifier
     *            the verifier to use.
     */
    public DefaultCallbackHandler(final CertificateVerifier verifier) {
        this.verifier = verifier;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void handle(final Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof CertificateVerificationCallback) {
                verify(CertificateVerificationCallback.class.cast(callback));
            } else {
                throw new UnsupportedCallbackException(callback);
            }
        }
    }

    /**
     * Verify the callback certificate.
     * 
     * @param callback
     *            the callback to verify.
     */
    private void verify(final CertificateVerificationCallback callback) {
        callback.setVerified(verifier.verify(callback.getCertificate()));
    }

}
