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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Attribute;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.cert.SubjectDirAttrExtension;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class SubjectDirectoryAttributes extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(SubjectDirectoryAttributes.class);

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.subjectDirectoryAttributes.getId());
		// Subject Directory Attributes must always be non-critical
		super.setCriticalFlag(false);
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) {
		ASN1Encodable ret = null;
		final String dirAttrString  = subject.getExtendedinformation() != null ? subject.getExtendedinformation().getSubjectDirectoryAttributes() : null;
		if (StringUtils.isNotEmpty(dirAttrString)) {
			// Subject Directory Attributes is a sequence of Attribute
			final Collection<Attribute> attr = SubjectDirAttrExtension.getSubjectDirectoryAttributes(dirAttrString);
			final ASN1EncodableVector vec = new ASN1EncodableVector();
			final Iterator<Attribute> iter = attr.iterator();
			while (iter.hasNext()) {
				vec.add(iter.next());
			}        
			if (vec.size() > 0) {
				ret = new DERSequence(vec);				
			}
		}			
		if (ret == null) {
			if (log.isDebugEnabled()) {
				log.debug("No directory attributes trying to create SubjectDirectoryAttributes extension: "+dirAttrString);
			}
		}
		return ret;
	}	
}
