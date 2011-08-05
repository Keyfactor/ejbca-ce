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
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtentionConfigurationException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/** AuthorityInformationAccess
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * Based on EJBCA version: AuthorityInformationAccess.java 11883 2011-05-04 08:52:09Z anatom $
 * 
 * @version $Id: AuthorityInformationAccess.java 740 2011-05-04 10:06:51Z tomas $
 */
public class AuthorityInformationAccess extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(AuthorityInformationAccess.class);


    @Override
    public void init(final CertificateProfile certProf) {
		super.setOID(X509Extensions.AuthorityInfoAccess.getId());
		super.setCriticalFlag(false);
	}
    
    @Override
	public DEREncodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		final ASN1EncodableVector accessList = new ASN1EncodableVector();
        GeneralName accessLocation;
        String url;

        // caIssuers
        final List<String> caIssuers = certProfile.getCaIssuers();
        if (caIssuers != null) {
        	for(final Iterator<String> it = caIssuers.iterator(); it.hasNext(); ) {
        		url = it.next();
        		if(StringUtils.isNotEmpty(url)) {
        			accessLocation = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(url));
        			accessList.add(new AccessDescription(AccessDescription.id_ad_caIssuers,
        					accessLocation));
        		}
        	}            	
        }

        // ocsp url
        final X509CA x509ca = (X509CA)ca;
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
