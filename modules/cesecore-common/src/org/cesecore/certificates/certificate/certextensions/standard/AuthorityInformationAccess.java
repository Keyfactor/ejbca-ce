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
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/** AuthorityInformationAccess
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @version $Id$
 */
public class AuthorityInformationAccess extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(AuthorityInformationAccess.class);


    @Override
    public void init(final CertificateProfile certProf) {
		super.setOID(Extension.authorityInfoAccess.getId());
		super.setCriticalFlag(false);
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws CertificateExtensionException {
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
            ret = org.bouncycastle.asn1.x509.AuthorityInformationAccess.getInstance(new DERSequence(accessList));
        }
		if (ret == null) {
			log.error("AuthorityInformationAccess is used, but nor caIssuers not Ocsp url are defined!");
		}
		return ret;
	}	
}
