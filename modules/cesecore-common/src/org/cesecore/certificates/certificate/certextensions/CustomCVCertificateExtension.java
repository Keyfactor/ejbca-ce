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
package org.cesecore.certificates.certificate.certextensions;

import java.security.PublicKey;

import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.cvc.CVCDiscretionaryDataTemplate;

/**
 * Additional interface for custom CV (Card Verifiable) Certificate extensions.
 * 
 * @version $Id$
 */
public interface CustomCVCertificateExtension extends CustomCertificateExtension {

    /**
     * Constructs the Discretionary Data Template object for the certificate extension.
     * @param userData End Entity information, or null in CSRs.
     * @param ca Issuing CA.
     * @param certProfile Certificate profile.
     * @param userPublicKey Public key of user.
     * @param caPublicKey Public key of CA, or null in CSRs.
     * @param validity Validity, or null in CSRs.
     * @param isCSR true if generating a CSR, false if generating a certificate.
     * @return The Discretionary Data Template object
     * @throws CertificateExtensionException In case of encoding errors etc.
     */
    CVCDiscretionaryDataTemplate getValueCVC(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity validity, boolean isCSR) throws CertificateExtensionException;
    
    /**
     * Returns true if the certificate is to be included in certificates (default: true).
     */
    boolean isIncludedInCertificates();
    
    /**
     * Returns true if the certificate is to be included in CSRs (default: false).
     */
    boolean isIncludedInCSR();
}
