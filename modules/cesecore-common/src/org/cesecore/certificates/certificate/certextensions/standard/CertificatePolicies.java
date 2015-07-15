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
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.DisplayText;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.asn1.x509.PolicyQualifierId;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificatePolicy;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.
 * 
 * @version $Id$
 */
public class CertificatePolicies extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(CertificatePolicies.class);
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.certificatePolicies.getId());
		super.setCriticalFlag(certProf.getCertificatePoliciesCritical());
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws
            CertificateExtensionException {
		DERSequence ret = null;
    	// The UserNotice policy qualifier can have two different character encodings,
    	// the correct one (UTF8) or the wrong one (BMP) used by IE < 7.
		final X509CA x509ca = (X509CA)ca;
    	int displayencoding = DisplayText.CONTENT_TYPE_BMPSTRING;
    	if (x509ca.getUseUTF8PolicyText()) {
    		displayencoding = DisplayText.CONTENT_TYPE_UTF8STRING;
    	}
    	// Iterate through policies and add oids and policy qualifiers if they exist
    	final List<CertificatePolicy> policies = certProfile.getCertificatePolicies();
    	final Map<ASN1ObjectIdentifier, ASN1EncodableVector> policiesMap = new HashMap<ASN1ObjectIdentifier, ASN1EncodableVector>();
    	// Each Policy OID can be entered several times, with different qualifiers, 
    	// because of this we make a map of oid and qualifiers, and we can add a new qualifier
    	// in each round of this for loop
    	for(final Iterator<CertificatePolicy> it = policies.iterator(); it.hasNext(); ) {
    		final CertificatePolicy policy = it.next();
    		final ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(policy.getPolicyID());
    		final ASN1EncodableVector qualifiers;
    		if(policiesMap.containsKey(oid)) {
    			qualifiers = policiesMap.get(oid);
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
    	for(final Iterator<ASN1ObjectIdentifier> it = policiesMap.keySet().iterator(); it.hasNext(); ) {
    		final ASN1ObjectIdentifier oid = it.next();
    		final ASN1EncodableVector qualifiers = policiesMap.get(oid);
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
			log.warn("Certificate policies missconfigured, no policies present!");
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
