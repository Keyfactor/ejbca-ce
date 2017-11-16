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

    CVCDiscretionaryDataTemplate getValueCVC(EndEntityInformation userData, CA ca, CertificateProfile certProfile, PublicKey userPublicKey,
            PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException;
    
}
