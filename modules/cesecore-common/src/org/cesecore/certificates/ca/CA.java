/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ca;

import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAService;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceInfo;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceNotActiveException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequest;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceRequestException;
import org.cesecore.certificates.ca.extendedservices.ExtendedCAServiceResponse;
import org.cesecore.certificates.ca.extendedservices.IllegalExtendedCAServiceRequestException;
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
import org.cesecore.util.CertTools;

/**
 * Common methods for unrestricted X509 and CVC CA implementations.
 */
public interface CA extends CACommon {
    
    long getCRLPeriod();

    void setCRLPeriod(long crlperiod);

    long getDeltaCRLPeriod();

    void setDeltaCRLPeriod(long deltacrlperiod);
    
    boolean getGenerateCrlUponRevocation();

    void setGenerateCrlUponRevocation(boolean generate);

    long getCRLIssueInterval();

    void setCRLIssueInterval(long crlIssueInterval);

    long getCRLOverlapTime();

    void setCRLOverlapTime(long crlOverlapTime);

    boolean getKeepExpiredCertsOnCRL();

    void setKeepExpiredCertsOnCRL(boolean keepexpiredcertsoncrl);

    int getDefaultCertificateProfileId();
    
    boolean isDoEnforceUniquePublicKeys();
    boolean isDoEnforceKeyRenewal();

    boolean isDoEnforceUniqueDistinguishedName();

    boolean isDoEnforceUniqueSubjectDNSerialnumber();

    /**
     * Whether certificate request history should be used or not. The default value here is
     * used when the value is missing in the database, and is true for compatibility with
     * old CAs since it was not configurable and always enabled before 3.10.4.
     * For new CAs the default value is set in the web or CLI code and is false since 6.0.0.
     */
    boolean isUseCertReqHistory();

    /** whether users should be stored or not, default true as was the case before 3.10.x */
    boolean isUseUserStorage();

    /** whether issued certificates should be stored or not, default true as was the case before 3.10.x */
    boolean isUseCertificateStorage();

    /** whether revocations for non existing entry accepted */
    boolean isAcceptRevocationNonExistingEntry();
    
    // Methods used with extended services

    /** Method used to retrieve information about the service. */
    ExtendedCAServiceInfo getExtendedCAServiceInfo(int type);

    /**
     * Method used to perform the service.
     * @throws OperatorCreationException
     * @throws CertificateException
     */
    ExtendedCAServiceResponse extendedService(CryptoToken cryptoToken, ExtendedCAServiceRequest request)
            throws ExtendedCAServiceRequestException, IllegalExtendedCAServiceRequestException, ExtendedCAServiceNotActiveException,
            CertificateException, OperatorCreationException;

    HashMap<?,?> getExtendedCAServiceData(int type);

    void setExtendedCAServiceData(int type, HashMap<?, ?> serviceData);

    void setExtendedCAService(ExtendedCAService extendedcaservice);

    /** Returns a Collection of ExternalCAServices (int) added to this CA. */
    Collection<Integer> getExternalCAServiceTypes();
    
    /**
     * Initializes the ExtendedCAService
     *
     * @param cryptoToken the cryptotoken used to initiate the service
     * @param type the type of the extended key service
     * @param ca the CA used to initiate the service
     * @param cceConfig containing a list of available custom certificate extensions
     */
    void initExtendedService(CryptoToken cryptoToken, int type, CA ca, AvailableCustomCertificateExtensionsConfiguration cceConfig) throws Exception;
    
    /**
    *
    * @param publicKey provided public key. Will not have any precedence over subject.extendedInformation.certificateRequest
    * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
    * @param notBefore null or a custom date to use as notBefore date
    * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
    * @param encodedValidity requested validity as SimpleTime string or ISO8601 date string (see ValidityDate.java).
    * @param certProfile
    * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
    *            CVC CAs for sequence field. Can be set to null.
    * @param cceConfig containing a list of available custom certificate extensions
    * @return The newly created certificate, never null
    * 
    * @throws CryptoTokenOfflineException if the crypto token was unavailable
    * @throws CertificateExtensionException  if any of the certificate extensions were invalid
    * @throws CertificateCreateException if an error occurred when trying to create a certificate.
    * @throws OperatorCreationException  if CA's private key contained an unknown algorithm or provider
    * @throws IllegalNameException if the name specified in the certificate request contains illegal characters
    * @throws IllegalValidityException  if validity was invalid
    * @throws InvalidAlgorithmException  if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
    * @throws CAOfflineException if the CA wasn't active
    * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
    * @throws IllegalKeyException if the using public key is not allowed to be used by specified certProfile
    */
    Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, PublicKey publicKey, int keyusage, Date notBefore,
            String encodedValidity, CertificateProfile certProfile, String sequence, AvailableCustomCertificateExtensionsConfiguration cceConfig)
            throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
            OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException;

   /**
    *
    * @param cryptoToken
    * @param request provided request message containing optional information, and will be set with the signing key and provider.
    * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
    * publicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
    * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
    * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
    * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
    * @param notBefore
    * @param notAfter
    * @param certProfile
    * @param extensions an optional set of extensions to set in the created certificate, if the profile allows extension override, null if the
    *            profile default extensions should be used.
    * @param sequence an optional requested sequence number (serial number) for the certificate, may or may not be used by the CA. Currently used by
    *            CVC CAs for sequence field. Can be set to null.
    * @param certGenParams Extra parameters for certificate generation, e.g. for the CT extension. May contain references to session beans.
    * @param cceConfig containing a list of available custom certificate extensions
    * @return the generated certificate, never null
    *
    * @throws CryptoTokenOfflineException if the crypto token was unavailable
    * @throws CertificateExtensionException  if any of the certificate extensions were invalid
    * @throws CertificateCreateException if an error occurred when trying to create a certificate.
    * @throws OperatorCreationException  if CA's private key contained an unknown algorithm or provider
    * @throws IllegalNameException if the name specified in the certificate request contains illegal characters
    * @throws IllegalValidityException  if validity was invalid
    * @throws InvalidAlgorithmException  if the signing algorithm in the certificate profile (or the CA Token if not found) was invalid.
    * @throws CAOfflineException if the CA wasn't active
    * @throws SignatureException if the CA's certificate's and request's certificate's and signature algorithms differ
    * @throws IllegalKeyException if the using public key is not allowed to be used by specified certProfile
    */
   Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request, PublicKey publicKey, int keyusage,
           Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
           CertificateGenerationParams certGenParams, AvailableCustomCertificateExtensionsConfiguration cceConfig)
           throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
           OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;

   /**
    *
    * @param request provided request message containing optional information, and will be set with the signing key and provider.
    * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Can be null. Its public key is going to be used if
    * publicKey == null && subject.extendedInformation.certificateRequest == null
    * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
    * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
    * 
    * @return the generated certificate, never null. 
    */
   Certificate generateCertificate(CryptoToken cryptoToken, EndEntityInformation subject, RequestMessage request, PublicKey publicKey, int keyusage,
           Date notBefore, Date notAfter, CertificateProfile certProfile, Extensions extensions, String sequence,
           AvailableCustomCertificateExtensionsConfiguration cceConfig)
           throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
           OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;

   X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber, Certificate partitionCaCert) throws Exception;
   
   X509CRLHolder generateCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber, Certificate partitionCaCert, final Date validFrom) throws Exception;

   default X509CRLHolder generateDeltaCRL(CryptoToken cryptoToken, int crlPartitionIndex, Collection<RevokedCertInfo> certs, int crlnumber, int basecrlnumber, Certificate latestCaCertForParition) throws Exception {
      throw new UnsupportedOperationException("This operation is not supported in this CA type!"); 
   }

   /**
    * Create a signed PKCS#7 / CMS message.
    *
    * @param cryptoToken
    * @param cert
    * @param includeChain
    * @return A DER-encoded PKCS#7
    * @throws SignRequestSignatureException if the certificate doesn't seem to be signed by this CA
    * @see CertTools#createCertsOnlyCMS(List) for how to craete a certs-only PKCS7/CMS
    */
   byte[] createPKCS7(CryptoToken cryptoToken, X509Certificate cert, boolean includeChain) throws SignRequestSignatureException;

   /**
    * Creates a roll over PKCS7 for the next CA certificate, signed with the current CA key. Used by ScepServlet.
    *
    * @return Encoded signed certificate chain, suitable for use in SCEP.
    */
   byte[] createPKCS7Rollover(CryptoToken cryptoToken) throws SignRequestSignatureException;

   /**
    * Creates a certificate signature request (CSR), that can be sent to an external Root CA. Request format can vary depending on the type of CA. For
    * X509 CAs PKCS#10 requests are created, for CVC CAs CVC requests are created.
    *
    * @param attributes PKCS10 attributes to be included in the request, a Collection of ASN1Encodable objects, ready to put in the request. Can be
    *            null.
    * @param signAlg the signature algorithm used by the CA
    * @param cacert the CAcertficate the request is targeted for, may be used or ignored by implementation depending on the request type created.
    * @param signatureKeyPurpose which CA token key pair should be used to create the request, normally SecConst.CAKEYPURPOSE_CERTSIGN but can also
    *            be SecConst.CAKEYPURPOSE_CERTSIGN_NEXT.
    * @param certificateProfile Certificate profile to use for CA-type specific purposes, such as CV Certificate Extensions.
    * @param cceConfig containing a list of available custom certificate extensions
    * @return byte array with binary encoded request
    * @throws CryptoTokenOfflineException if the crypto token is offline
    * @throws CertificateExtensionException if there was a problem constructing a certificate extension.
    */
   byte[] createRequest(CryptoToken cryptoToken, Collection<ASN1Encodable> attributes, String signAlg, Certificate cacert, int signatureKeyPurpose,
           CertificateProfile certificateProfile, AvailableCustomCertificateExtensionsConfiguration cceConfig)
           throws CryptoTokenOfflineException, CertificateExtensionException;

   byte[] createAuthCertSignRequest(CryptoToken cryptoToken, byte[] request) throws CryptoTokenOfflineException;
   

}