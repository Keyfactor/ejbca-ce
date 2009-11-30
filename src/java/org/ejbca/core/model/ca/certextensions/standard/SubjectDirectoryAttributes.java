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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.cert.SubjectDirAttrExtension;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class SubjectDirectoryAttributes extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(SubjectDirectoryAttributes.class);

	/**
	 * Constructor for creating the certificate extension 
	 */
	public SubjectDirectoryAttributes() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(X509Extensions.SubjectDirectoryAttributes.getId());
		// Subject Directory Attributes must always be non-critical
		super.setCriticalFlag(false);
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
	public DEREncodable getValue(UserDataVO subject, CA ca, CertificateProfile certProfile, PublicKey userPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		DEREncodable ret = null;
		String dirAttrString = subject.getExtendedinformation().getSubjectDirectoryAttributes();
		if (StringUtils.isNotEmpty(dirAttrString)) {
			// Subject Directory Attributes is a sequence of Attribute
			Collection attr = SubjectDirAttrExtension.getSubjectDirectoryAttributes(dirAttrString);
			ASN1EncodableVector vec = new ASN1EncodableVector();
			Iterator iter = attr.iterator();
			while (iter.hasNext()) {
				Attribute a = (Attribute)iter.next();
				vec.add(a);
			}        
			if (vec.size() > 0) {
				ret = new DERSequence(vec);				
			}
		}			
		if (ret == null) {
			log.debug("No directory attributes trying to create SubjectDirectoryAttributes extension: "+dirAttrString);
		}
		return ret;
	}	
}
