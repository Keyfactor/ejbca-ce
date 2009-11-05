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
import java.util.Iterator;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/** AuthorityInformationAccess
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class AuthorityInformationAccess extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(AuthorityInformationAccess.class);

	/**
	 * Constructor for creating the certificate extension 
	 */
	public AuthorityInformationAccess() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
		super.setOID(X509Extensions.AuthorityInfoAccess.getId());
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
        ASN1EncodableVector accessList = new ASN1EncodableVector();
        GeneralName accessLocation;
        String url;

        // caIssuers
        List caIssuers = certProfile.getCaIssuers();
        if (caIssuers != null) {
        	for(Iterator it = caIssuers.iterator(); it.hasNext(); ) {
        		url = (String) it.next();
        		if(StringUtils.isNotEmpty(url)) {
        			accessLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
        			accessList.add(new AccessDescription(AccessDescription.id_ad_caIssuers,
        					accessLocation));
        		}
        	}            	
        }

        // ocsp url
        X509CA x509ca = (X509CA)ca;
        url = certProfile.getOCSPServiceLocatorURI();
        if(certProfile.getUseDefaultOCSPServiceLocator()){
        	url = x509ca.getDefaultOCSPServiceLocator();
        }
        if (StringUtils.isNotEmpty(url)) {
        	accessLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
        	accessList.add(new AccessDescription(AccessDescription.id_ad_ocsp,
        			accessLocation));
        }
        org.bouncycastle.asn1.x509.AuthorityInformationAccess ret = null;
        if (accessList.size() > 0) {        	
            ret = new org.bouncycastle.asn1.x509.AuthorityInformationAccess(new DERSequence(accessList));
        }
		if (ret == null) {
			log.error("AuthorityInformationAccess is used, but nor caIssuers not Ocsp url are defined!");
		}
		return ret;
	}	
}
