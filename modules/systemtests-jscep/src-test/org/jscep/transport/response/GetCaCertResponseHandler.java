package org.jscep.transport.response;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.util.SignedDataUtils;

/**
 * This class handles responses to <code>GetCACert</code> requests.
 */
@ThreadSafe
public final class GetCaCertResponseHandler implements
        ScepResponseHandler<CertStore> {
    private static final String RA_CERT = "application/x-x509-ca-ra-cert";
    private static final String CA_CERT = "application/x-x509-ca-cert";

    /**
     * {@inheritDoc}
     */
    @Override
    public CertStore getResponse(final byte[] content, final String mimeType)
            throws ContentException {
        if (mimeType != null && mimeType.startsWith(CA_CERT)) {
            // http://tools.ietf.org/html/draft-nourse-scep-20#section-4.1.1.1
            CertificateFactory factory;
            try {
                factory = CertificateFactory.getInstance("X509");
            } catch (CertificateException e) {
                throw new RuntimeException(e);
            }
            try {
                X509Certificate ca = (X509Certificate) factory
                        .generateCertificate(new ByteArrayInputStream(content));
                Collection<X509Certificate> caSet = Collections.singleton(ca);
                CertStoreParameters storeParams = new CollectionCertStoreParameters(
                        caSet);

                return CertStore.getInstance("Collection", storeParams);
            } catch (GeneralSecurityException e) {
                throw new InvalidContentTypeException(e);
            }
        } else if (mimeType != null && mimeType.startsWith(RA_CERT)) {
            // If an RA is in use, a certificates-only PKCS#7 SignedData
            // with a certificate chain consisting of both RA and CA
            // certificates is
            // returned.
            // It should be in the order:
            // [0] RA
            // [1] CA
            if (content.length == 0) {
                throw new InvalidContentException(
                        "Expected a SignedData object, but response was empty");
            }
            CMSSignedData sd;
            try {
                sd = new CMSSignedData(content);
            } catch (CMSException e) {
                throw new InvalidContentException(e);
            }
            return SignedDataUtils.fromSignedData(sd);
        } else {
            throw new InvalidContentTypeException(mimeType, CA_CERT, RA_CERT);
        }
    }
}
