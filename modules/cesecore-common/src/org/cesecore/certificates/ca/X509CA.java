/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.io.IOException;
import java.security.cert.Certificate;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.cesecore.certificates.certificate.certextensions.AvailableCustomCertificateExtensionsConfiguration;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;

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

    void createOrRemoveLinkCertificateDuringCANameChange(CryptoToken cryptoToken, boolean createLinkCertificate, CertificateProfile certProfile,
            AvailableCustomCertificateExtensionsConfiguration cceConfig, Certificate oldCaCert) throws CryptoTokenOfflineException;

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