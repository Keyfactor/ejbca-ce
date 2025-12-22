package org.jscep.client.verification;

import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.commons.lang3.ArrayUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This {@code CertificateVerifier} uses a pre-provisioned message digest to
 * verify the certificate.
 * <p>
 * Typically, we expect the hash to be provided out of band, often as a
 * hexadecimal string.
 * 
 * <pre>
 * MessageDigest digest = MessageDigest.getInstance(&quot;MD5&quot;);
 * byte[] expected = Hex.decode(&quot;835f179febba96f32a47610a679de400&quot;.toCharArray());
 * 
 * new MessageDigestCertificateVerifier(digest, expected);
 * </pre>
 */
public final class MessageDigestCertificateVerifier implements
        CertificateVerifier {
    private static final Logger LOGGER = LoggerFactory
            .getLogger(MessageDigestCertificateVerifier.class);

    /**
     * The digest to use.
     */
    private final MessageDigest digest;
    /**
     * The expected digest outcome.
     */
    private final byte[] expected;

    /**
     * Creates a new instance with a digest algorithm, and the expected digest
     * result.
     * 
     * @param digest
     *            the digest algorithm to for verification.
     * @param expected
     *            the digest result
     */
    public MessageDigestCertificateVerifier(final MessageDigest digest,
            final byte[] expected) {
        this.digest = digest;
        this.expected = ArrayUtils.clone(expected);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(final X509Certificate cert) {
        try {
            digest.reset();
            byte[] actual = digest.digest(cert.getEncoded());
            if(Arrays.equals(actual, expected))
            {
                return true;
            }

            // the following code is for backwards compatibility
            actual = digest.digest(cert.getTBSCertificate());
            if(Arrays.equals(actual, expected))
            {
                LOGGER.warn("MessageDigest over the Certificate.tbsCertificate is configured, "
                        + "but it should be over the DER encoded Certificate");
                return true;
            } else
            {
                return false;
            }
        } catch (CertificateEncodingException e) {
            return false;
        }
    }
}
