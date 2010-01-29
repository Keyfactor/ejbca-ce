/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.ca.certextensions.standard;

import java.security.PublicKey;
import java.util.Collection;
import java.util.Iterator;
import java.util.Vector;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class ExtendedKeyUsage extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(ExtendedKeyUsage.class);
	/**
	 * Constructor for creating the certificate extension 
	 */
	public ExtendedKeyUsage() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(X509Extensions.ExtendedKeyUsage.getId());
        // Extended Key Usage may be either critical or non-critical
		super.setCriticalFlag(certProf.getExtendedKeyUsageCritical());
	}
	/**
	 * Method that should return the DEREncodable value used in the extension
	 * this is the method at all implementors must implement.
	 * 
	 * @param userData the userdata of the issued certificate.
	 * @param ca the CA data with access to all the keys etc
	 * @param certProfile the certificate profile
	 * @return a DEREncodable or null.
	 */
	public DEREncodable getValue(UserDataVO subject, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		org.bouncycastle.asn1.x509.ExtendedKeyUsage ret = null;
        // Get extended key usage from certificate profile
        Collection c = certProfile.getExtendedKeyUsageOids();
        Vector usage = new Vector();
        Iterator iter = c.iterator();
        while (iter.hasNext()) {
            usage.add(new DERObjectIdentifier((String)iter.next()));
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
