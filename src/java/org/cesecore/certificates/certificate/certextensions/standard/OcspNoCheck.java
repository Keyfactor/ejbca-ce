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
package org.cesecore.certificates.certificate.certextensions.standard;

import java.security.PublicKey;

import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/** OCSP nocheck extension (rfc 2560)
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * Based on EJBCA version: OcspNoCheck.java 11883 2011-05-04 08:52:09Z anatom $
 * 
 * @version $Id$
 */
public class OcspNoCheck extends StandardCertificateExtension {
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(OCSPObjectIdentifiers.id_pkix_ocsp_nocheck.getId());
		super.setCriticalFlag(false);
	}
    
    @Override
	public DEREncodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		return new DERNull();
	}	
}
