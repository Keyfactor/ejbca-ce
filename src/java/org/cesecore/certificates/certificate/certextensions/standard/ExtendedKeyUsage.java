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
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * Based on EJBCA version: ExtendedKeyUsage.java 11883 2011-05-04 08:52:09Z anatom $
 * 
 * @version $Id$
 */
public class ExtendedKeyUsage extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(ExtendedKeyUsage.class);

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(X509Extensions.ExtendedKeyUsage.getId());
        // Extended Key Usage may be either critical or non-critical
		super.setCriticalFlag(certProf.getExtendedKeyUsageCritical());
	}
    
    @Override
	public DEREncodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		org.bouncycastle.asn1.x509.ExtendedKeyUsage ret = null;
        // Get extended key usage from certificate profile
		final Collection<String> c = certProfile.getExtendedKeyUsageOids();
		final Vector<DERObjectIdentifier> usage = new Vector<DERObjectIdentifier>();
		final Iterator<String> iter = c.iterator();
        while (iter.hasNext()) {
            usage.add(new DERObjectIdentifier(iter.next()));
        }
        // Don't add empty key usage extension
        if (!usage.isEmpty()) {
            ret = new org.bouncycastle.asn1.x509.ExtendedKeyUsage(usage);
        }
		if (ret == null) {
			log.error("ExtendedKeyUsage missconfigured, no oids defined");
		}
		return ret;
	}	
}
