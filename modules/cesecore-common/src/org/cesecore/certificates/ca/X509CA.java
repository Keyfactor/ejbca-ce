package org.cesecore.certificates.ca;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;

/**
 * CA operations used for X509 implementations specifically.
 * @version $Id$
 *
 */
public interface X509CA extends CA {

    List<CertificatePolicy> getPolicies();

    void setPolicies(List<CertificatePolicy> policies);

    boolean getUseAuthorityKeyIdentifier();

    void setUseAuthorityKeyIdentifier(boolean useauthoritykeyidentifier);

    boolean getAuthorityKeyIdentifierCritical();

    void setAuthorityKeyIdentifierCritical(boolean authoritykeyidentifiercritical);

    /** CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
     *
     * @return List of strings
     */
    List<String> getAuthorityInformationAccess();

    /** CA Issuer URI to put in CRLs (RFC5280 section 5.2.7, not the URI to put in certs
     *
     * @param authorityInformationAccess List of strings
     */
    void setAuthorityInformationAccess(List<String> authorityInformationAccess);

    List<String> getCertificateAiaDefaultCaIssuerUri();

    void setCertificateAiaDefaultCaIssuerUri(List<String> uris);

    boolean getUseCRLNumber();

    void setUseCRLNumber(boolean usecrlnumber);

    boolean getCRLNumberCritical();

    void setCRLNumberCritical(boolean crlnumbercritical);

    String getDefaultCRLDistPoint();

    void setDefaultCRLDistPoint(String defaultcrldistpoint);

    String getDefaultCRLIssuer();

    void setDefaultCRLIssuer(String defaultcrlissuer);

    String getCADefinedFreshestCRL();

    void setCADefinedFreshestCRL(String cadefinedfreshestcrl);

    String getDefaultOCSPServiceLocator();

    void setDefaultOCSPServiceLocator(String defaultocsplocator);

    boolean getUseUTF8PolicyText();

    void setUseUTF8PolicyText(boolean useutf8);

    boolean getUsePrintableStringSubjectDN();

    void setUsePrintableStringSubjectDN(boolean useprintablestring);

    boolean getUseLdapDNOrder();

    void setUseLdapDNOrder(boolean useldapdnorder);

    boolean getUseCrlDistributionPointOnCrl();

    void setUseCrlDistributionPointOnCrl(boolean useCrlDistributionPointOnCrl);

    boolean getCrlDistributionPointOnCrlCritical();

    void setCrlDistributionPointOnCrlCritical(boolean crlDistributionPointOnCrlCritical);

    /** @return Encoded name constraints to permit */
    List<String> getNameConstraintsPermitted();

    void setNameConstraintsPermitted(List<String> encodedNames);

    /** @return Encoded name constraints to exclude */
    List<String> getNameConstraintsExcluded();

    void setNameConstraintsExcluded(List<String> encodedNames);

    String getCmpRaAuthSecret();

    void setCmpRaAuthSecret(String cmpRaAuthSecret);

    Integer getSerialNumberOctetSize();

    void setCaSerialNumberOctetSize(int serialNumberOctetSize);

    void updateCA(CryptoToken cryptoToken, CAInfo cainfo, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws InvalidAlgorithmException;

    /**
     * Allows updating of fields that are otherwise not changeable in existing CAs.
     */
    void updateUninitializedCA(CAInfo cainfo);

    byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException;

    byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException;

    /**
     * @see CA#createRequest(CryptoToken, Collection, String, Certificate, int, CertificateProfile, AvailableCustomCertificateExtensionsConfiguration)
     */
    byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose,
            CertificateProfile certificateProfile, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CertificateExtensionException;

    /** This method is not supported for X509 CAs. */
    byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException;

    void createOrRemoveLinkCertificateDuringCANameChange(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException;

    void createOrRemoveLinkCertificate(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException;

    /**
     * @param request provided request message containing optional information, and will be set with the signing key and provider.
     * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
     * publicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
     * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
     * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
     */
    Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request, PublicKey publicKey, int keyusage,
            Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
            CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;

    X509CRLHolder generateCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber)
            throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException,
            InvalidKeyException, CRLException, NoSuchAlgorithmException;

    X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber)
            throws CryptoTokenOfflineException, IllegalCryptoTokenException, IOException, SignatureException, NoSuchProviderException,
            InvalidKeyException, CRLException, NoSuchAlgorithmException;


    
    /** Implementation of UpgradableDataHashMap function getLatestVersion */
    float getLatestVersion();

    byte[] decryptData(CryptoToken cryptoToken, byte[] data, int cAKeyPurpose) throws CMSException, CryptoTokenOfflineException;

    byte[] encryptData(CryptoToken cryptoToken, byte[] data, int keyPurpose)
            throws IOException, CMSException, CryptoTokenOfflineException, NoSuchAlgorithmException, NoSuchProviderException;

    void setUsePartitionedCrl(boolean usePartitionedCrl);

    boolean getUsePartitionedCrl();

    int getCrlPartitions();

    void setCrlPartitions(int crlPartitions);

    int getRetiredCrlPartitions();

    void setRetiredCrlPartitions(int retiredCrlPartitions);

    /**
     * Constructs the SubjectAlternativeName extension that will end up on the generated certificate.
     *
     * If the DNS values in the subjectAlternativeName extension contain parentheses to specify labels that should be redacted, the parentheses are removed and another extension
     * containing the number of redacted labels is added.
     *
     * @param subAltNameExt
     * @param publishToCT
     * @return An extension generator containing the SubjectAlternativeName extension and an extension holding the number of redacted labels if the certificate is to be published
     * to a CTLog
     * @throws IOException
     */
    ExtensionsGenerator getSubjectAltNameExtensionForCert(Extension subAltNameExt, boolean publishToCT) throws IOException;

    /**
     * Constructs the SubjectAlternativeName extension that will end up on the certificate published to a CTLog
     *
     * If the DNS values in the subjectAlternativeName extension contain parentheses to specify labels that should be redacted, these labels will be replaced by the string "PRIVATE"
     *
     * @param subAltNameExt
     * @returnAn extension generator containing the SubjectAlternativeName extension
     * @throws IOException
     */
    ExtensionsGenerator getSubjectAltNameExtensionForCTCert(Extension subAltNameExt) throws IOException;

}