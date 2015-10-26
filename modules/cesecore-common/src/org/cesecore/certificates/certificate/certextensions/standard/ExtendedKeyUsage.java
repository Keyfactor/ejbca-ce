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

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class ExtendedKeyUsage extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(ExtendedKeyUsage.class);

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.extendedKeyUsage.getId());
        // Extended Key Usage may be either critical or non-critical
		super.setCriticalFlag(certProf.getExtendedKeyUsageCritical());
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
		org.bouncycastle.asn1.x509.ExtendedKeyUsage ret = null;
		// Get extended key usage from certificate profile
		final Collection<String> oids = certProfile.getExtendedKeyUsageOids();
		
		// Don't add empty key usage extension
		if (oids.size() != 0) {
			final ASN1Encodable[] usage = new ASN1Encodable[oids.size()];
			int i = 0;
			for (String oid : oids) {
				usage[i] = org.bouncycastle.asn1.x509.KeyPurposeId.getInstance(new ASN1ObjectIdentifier(oid));
				i++;
			}
			
			ASN1Sequence seq = ASN1Sequence.getInstance(new DERSequence(usage));
			ret = org.bouncycastle.asn1.x509.ExtendedKeyUsage.getInstance(seq);
		}
		if (ret == null) {
			log.error("ExtendedKeyUsage missconfigured, no oids defined");
		}
		return ret;
	}	
}
