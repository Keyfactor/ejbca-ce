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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.jce.X509KeyUsage;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class KeyUsage extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(KeyUsage.class);

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.keyUsage.getId());
		super.setCriticalFlag(certProf.getKeyUsageCritical());
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws
            CertificateExtensionException {
		// Key usage
		X509KeyUsage ret = null;
		final int keyUsage = CertTools.sunKeyUsageToBC(certProfile.getKeyUsage());
		if (log.isDebugEnabled()) {
			log.debug("Using KeyUsage from profile: "+keyUsage);
		}
		if (keyUsage >=0) {
			ret = new X509KeyUsage(keyUsage);
		}
		if (ret == null) {
			log.error("KeyUsage missconfigured, key usage flag invalid: "+keyUsage);
		}
		return ret;
	}	
}
