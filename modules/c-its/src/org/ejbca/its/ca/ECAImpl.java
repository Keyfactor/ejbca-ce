package org.ejbca.its.ca;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.CABase;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;

public class ECAImpl extends CABase implements Serializable {

    @Override
    public Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request, PublicKey publicKey,
            int keyusage, Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber,
            Certificate partitionCaCert) throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber,
            int basecrlnumber, Certificate latestCaCertForParition) throws Exception {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert,
            int signatureKeyPurpose, CertificateProfile certificateProfile, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CertificateExtensionException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public String getCaImplType() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException {
        // TODO Auto-generated method stub

    }

    @Override
    public float getLatestVersion() {
        // TODO Auto-generated method stub
        return 0;
    }

}
