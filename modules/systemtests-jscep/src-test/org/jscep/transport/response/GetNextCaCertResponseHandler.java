package org.jscep.transport.response;

import java.io.IOException;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;

import net.jcip.annotations.ThreadSafe;

import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.jscep.util.SignedDataUtils;

/**
 * This class handles responses to <code>GetNextCACert</code> requests.
 */
@ThreadSafe
public final class GetNextCaCertResponseHandler implements
        ScepResponseHandler<CertStore> {
    private static final String NEXT_CA_CERT = "application/x-x509-next-ca-cert";
    private final X509Certificate signer;

    /**
     * Creates a new {@code GetNextCaCertResponseHandler} using the provided
     * certificate.
     *
     * @param signer
     *            the signer of the {@code signedData} response.
     */
    public GetNextCaCertResponseHandler(final X509Certificate signer) {
        this.signer = signer;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public CertStore getResponse(final byte[] content,
            final String mimeType) throws ContentException {
        if (mimeType.startsWith(NEXT_CA_CERT)) {
            // http://tools.ietf.org/html/draft-nourse-scep-20#section-4.6.1

            // The response consists of a SignedData PKCS#7 [RFC2315],
            // signed by the current CA (or RA) signing key.
            try {
                CMSSignedData cmsMessageData = new CMSSignedData(content);
                ContentInfo cmsContentInfo = ContentInfo
                        .getInstance(cmsMessageData.getEncoded());

                final CMSSignedData sd = new CMSSignedData(cmsContentInfo);
                if (!SignedDataUtils.isSignedBy(sd, signer)) {
                    throw new InvalidContentException("Invalid Signer");
                }
                // The content of the SignedData PKCS#7 [RFC2315] is a
                // degenerate
                // certificates-only Signed-data (Section 3.3) message
                // containing the
                // new CA certificate and any new RA certificates, as defined in
                // Section 5.2.1.1.2, to be used when the current CA certificate
                // expires.
                return SignedDataUtils.fromSignedData(sd);
            } catch (IOException e) {
                throw new InvalidContentTypeException(e);
            } catch (CMSException e) {
                throw new InvalidContentTypeException(e);
            }
        } else {
            throw new InvalidContentTypeException(mimeType, NEXT_CA_CERT);
        }
    }
}
