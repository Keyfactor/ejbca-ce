package org.jscep.client.verification;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * This {@code CertificateVerifier} delegates verification to the provided
 * {@code CertificateVerifier} and caches the answer.
 */
public final class CachingCertificateVerifier implements CertificateVerifier {
    /**
     * Previously received verification answers.
     */
    private final Map<Certificate, Boolean> verificationAnswers;
    /**
     * The verifier to delegate to.
     */
    private final CertificateVerifier delegate;

    /**
     * Constructs a {@code CachingCertificateVerifier} which delegates to the
     * specified {@code CertificateVerifier}.
     * 
     * @param delegate
     *            the {@code CertificateVerifier} to delegate to.
     */
    public CachingCertificateVerifier(final CertificateVerifier delegate) {
        this.delegate = delegate;
        this.verificationAnswers = new HashMap<Certificate, Boolean>();
    }

    /**
     * This implementation will forward the given certificate to the delegate
     * provided in the constructor, and cache the delegate's response.
     * <p>
     * On every subsequent invocation with the same certificate, the initial
     * response from the delegate will be returned.
     * 
     * @param cert
     *            the certificate to verify.
     * @return the result of calling {@code verify} on the delegate
     *         {@code CertificateVerifier}.
     */
    @Override
    public synchronized boolean verify(final X509Certificate cert) {
        if (verificationAnswers.containsKey(cert)) {
            return verificationAnswers.get(cert);
        } else {
            boolean answer = delegate.verify(cert);
            verificationAnswers.put(cert, answer);

            return answer;
        }
    }

}
