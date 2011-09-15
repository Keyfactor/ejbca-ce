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
import org.bouncycastle.asn1.DERIA5String;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

/** Microsoft Template extension, for domain controllers
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * Based on EJBCA version: MsTemplate.java 11883 2011-05-04 08:52:09Z anatom $
 * 
 * @version $Id$
 */
public class MsTemplate extends StandardCertificateExtension {
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(CertTools.OID_MSTEMPLATE);
		super.setCriticalFlag(false);
	}
    
    @Override
	public DEREncodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		final String mstemplate = certProfile.getMicrosoftTemplate();             
        return new DERIA5String(mstemplate);             
	}	
}
