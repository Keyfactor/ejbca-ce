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
import java.util.Date;

import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

/**
 * Interface defining methods for CA's that support hybrid certificates, i.e. certificates that may contain an alternative signing key and signature.
 */
public interface HybridCa {
    
   /**
    *
    * @param cryptoToken the CA's crypto token
    * @param alternativeCryptoToken the crypto token containing the alternative keys. null if not used. 
    * @param request provided request message containing optional information, and will be set with the signing key and provider.
    * If the certificate profile allows subject DN override this value will be used instead of the value from subject.getDN. Its public key is going to be used if
    * publicKey == null && subject.extendedInformation.certificateRequest == null. Can be null.
    * @param publicKey provided public key which will have precedence over public key from the provided RequestMessage but not over subject.extendedInformation.certificateRequest
    * @param subject end entity information. If it contains certificateRequest under extendedInformation, it will be used instead of the provided RequestMessage and publicKey
    * @param keyusage BouncyCastle key usage {@link X509KeyUsage}, e.g. X509KeyUsage.digitalSignature | X509KeyUsage.keyEncipherment
    * @param notBefore the notBefore date of the certificate
    * @param notAfter the notAfter date of the certificate
    * @param certProfile the appliced certificate profile
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
   Certificate generateCertificate(final CryptoToken cryptoToken, final CryptoToken alternativeCryptoToken, final EndEntityInformation subject,
           final RequestMessage request, final PublicKey publicKey, final int keyusage, final Date notBefore, final Date notAfter,
           final CertificateProfile certProfile, final Extensions extensions, final String sequence, final CertificateGenerationParams certGenParams,
           final AvailableCustomCertificateExtensionsConfiguration cceConfig)
           throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
           OperatorCreationException, CertificateCreateException, CertificateExtensionException, SignatureException, IllegalKeyException;
   
   
   /**
   *
   * @param cryptoToken the CA's crypto token
   * @param alternativeCryptoToken the crypto token containing the alternative keys. null if not used. 
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
   Certificate generateCertificate(final CryptoToken cryptoToken, final CryptoToken alternativeCryptoToken, EndEntityInformation subject, PublicKey publicKey, int keyusage, Date notBefore,
           String encodedValidity, CertificateProfile certProfile, String sequence, AvailableCustomCertificateExtensionsConfiguration cceConfig)
           throws CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException, IllegalNameException,
           OperatorCreationException, CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException;

}
