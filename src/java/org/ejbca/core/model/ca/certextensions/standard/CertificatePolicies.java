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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificatePolicy;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class CertificatePolicies extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(CertificatePolicies.class);
	
	@Override
	public void init(final CertificateProfile certProf) {
		super.setOID(X509Extensions.CertificatePolicies.getId());
		super.setCriticalFlag(certProf.getCertificatePoliciesCritical());
	}
	
	@Override
	public DEREncodable getValue(final UserDataVO subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		DERSequence ret = null;
    	// The UserNotice policy qualifier can have two different character encodings,
    	// the correct one (UTF8) or the wrong one (BMP) used by IE < 7.
		final X509CA x509ca = (X509CA)ca;
    	int displayencoding = DisplayText.CONTENT_TYPE_BMPSTRING;
    	if (x509ca.getUseUTF8PolicyText()) {
    		displayencoding = DisplayText.CONTENT_TYPE_UTF8STRING;
    	}
    	// Iterate through policies and add oids and policy qualifiers if they exist
    	final List policies = certProfile.getCertificatePolicies();
    	final Map policiesMap = new HashMap(); //<DERObjectIdentifier, ASN1EncodableVector>
    	// Each Policy OID can be entered several times, with different qualifiers, 
    	// because of this we make a map of oid and qualifiers, and we can add a new qualifier
    	// in each round of this for loop
    	for(final Iterator it = policies.iterator(); it.hasNext(); ) {
    		final CertificatePolicy policy = (CertificatePolicy) it.next();
    		final DERObjectIdentifier oid = new DERObjectIdentifier(policy.getPolicyID());
    		final ASN1EncodableVector qualifiers;
    		if(policiesMap.containsKey(oid)) {
    			qualifiers = (ASN1EncodableVector) policiesMap.get(oid);
    		} else {
    			qualifiers = new ASN1EncodableVector();
    		}
    		final PolicyQualifierInfo pqi = getPolicyQualifierInformation(policy, displayencoding);
			if (pqi != null) {
				qualifiers.add(pqi);
			}
			policiesMap.put(oid, qualifiers);
    	}
    	final ASN1EncodableVector seq = new ASN1EncodableVector();
    	for(final Iterator it = policiesMap.keySet().iterator(); it.hasNext(); ) {
    		final DERObjectIdentifier oid = (DERObjectIdentifier) it.next();
    		final ASN1EncodableVector qualifiers = (ASN1EncodableVector) policiesMap.get(oid);
    		if(qualifiers.size() == 0) {
    			seq.add(new PolicyInformation(oid, null));
    		} else {
    			seq.add(new PolicyInformation(oid, new DERSequence(qualifiers)));
    		}
    	}
    	if (seq.size() > 0) {
    		ret = new DERSequence(seq);        		
    	}
		if (ret == null) {
			log.error("Certificate policies missconfigured, no policies present!");
		}
		return ret;
	}	
	
    /**
     * Obtains the Policy Qualifier Information object
     * 
     * @param policy,
     *          CertificatePolicy with oid, user notice and cps uri
     * @param displayencoding,
     *          the encoding used for UserNotice text, DisplayText.CONTENT_TYPE_BMPSTRING, CONTENT_TYPE_UTF8STRING, CONTENT_TYPE_IA5STRING or CONTENT_TYPE_VISIBLESTRING 
     *          
     * @return PolicyQualifierInfo
     */
	private PolicyQualifierInfo getPolicyQualifierInformation(final CertificatePolicy policy, final int displayencoding) {
		PolicyQualifierInfo pqi = null;
		final String qualifierId = policy.getQualifierId();
		if ((qualifierId != null) && !StringUtils.isEmpty(qualifierId.trim())) {
			final String qualifier = policy.getQualifier();
			if ( (qualifier != null) && !StringUtils.isEmpty(qualifier.trim()) ) {
				if (qualifierId.equals(PolicyQualifierId.id_qt_cps.getId())) {
					pqi = new PolicyQualifierInfo(qualifier);
				} else if (qualifierId.equals(PolicyQualifierId.id_qt_unotice.getId())){
					// Normally we would just use 'DisplayText(unotice)' here. IE has problems with UTF8 though, so lets stick with BMSSTRING to satisfy Bills sick needs.
					final UserNotice un = new UserNotice(null, new DisplayText(displayencoding, qualifier));
					pqi = new PolicyQualifierInfo(PolicyQualifierId.id_qt_unotice, un);
				}
			}
		}
		return pqi;
	}   

}
