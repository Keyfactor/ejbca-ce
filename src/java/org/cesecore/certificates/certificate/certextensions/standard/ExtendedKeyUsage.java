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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class ExtendedKeyUsage extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(ExtendedKeyUsage.class);

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.extendedKeyUsage.getId());
        // Extended Key Usage may be either critical or non-critical
		super.setCriticalFlag(certProf.getExtendedKeyUsageCritical());
	}
    
    @Override
	public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		org.bouncycastle.asn1.x509.ExtendedKeyUsage ret = null;
        // Get extended key usage from certificate profile
		final Collection<String> c = certProfile.getExtendedKeyUsageOids();
		final Vector<ASN1ObjectIdentifier> usage = new Vector<ASN1ObjectIdentifier>();
		final Iterator<String> iter = c.iterator();
        while (iter.hasNext()) {
            usage.add(new ASN1ObjectIdentifier(iter.next()));
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
