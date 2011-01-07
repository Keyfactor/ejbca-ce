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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.X509CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.util.StringTools;

/** 
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @author: Tomas Gustavsson
 * @version $Id$
 */
public class CrlDistributionPoints extends StandardCertificateExtension {
    private static final Logger log = Logger.getLogger(CrlDistributionPoints.class);
	
	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(final CertificateProfile certProf) {
		super.setOID(X509Extensions.CRLDistributionPoints.getId());
		super.setCriticalFlag(certProf.getCRLDistributionPointCritical());
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
	public DEREncodable getValue(final UserDataVO subject, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		String crldistpoint = certProfile.getCRLDistributionPointURI();
		String crlissuer=certProfile.getCRLIssuer();
		final X509CA x509ca = (X509CA)ca;
		if(certProfile.getUseDefaultCRLDistributionPoint()){
			crldistpoint = x509ca.getDefaultCRLDistPoint();
			crlissuer = x509ca.getDefaultCRLIssuer();
		}
		// Multiple CDPs are separated with the ';' sign        	         	 
		final ArrayList<DistributionPointName> dpns = new ArrayList<DistributionPointName>();
		if (StringUtils.isNotEmpty(crldistpoint)) {
			final Iterator<String> it = StringTools.splitURIs(crldistpoint).iterator();
			while (it.hasNext()) {
				// 6 is URI
				final String uri = (String) it.next();
				final GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
				if (log.isDebugEnabled()) {
					log.debug("Added CRL distpoint: "+uri);
				}
				final ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				final GeneralNames gns = new GeneralNames(new DERSequence(vec));
				final DistributionPointName dpn = new DistributionPointName(0, gns);
				dpns.add(dpn);
			}            	
		}
		// CRL issuer works much like Dist point URI. If separated by ; it is put in the same global distPoint as the URI, 
		// if there is more of one of them, the one with more is put in an own global distPoint.
		final ArrayList<GeneralNames> issuers = new ArrayList<GeneralNames>();
		if (StringUtils.isNotEmpty(crlissuer)) {
			final StringTokenizer tokenizer = new StringTokenizer(crlissuer, ";", false);
			while (tokenizer.hasMoreTokens()) {
				final String issuer = tokenizer.nextToken();
				final GeneralName gn = new GeneralName(new X509Name(issuer));
				if (log.isDebugEnabled()) {
					log.debug("Added CRL issuer: "+issuer);
				}
				final ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				final GeneralNames gns = new GeneralNames(new DERSequence(vec));
				issuers.add(gns);
			}            	
		}
		final ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
		if ( (!issuers.isEmpty()) || (!dpns.isEmpty()) ) {
			int i = dpns.size();
			if (issuers.size() > i) {
				i = issuers.size();
			}
			for (int j = 0; j < i; j++) {
				DistributionPointName dpn = null;
				GeneralNames issuer = null;
				if (dpns.size() > j) {
					dpn = (DistributionPointName)dpns.get(j);
				}
				if (issuers.size() > j) {
					issuer = (GeneralNames)issuers.get(j);
				}
				if ( (dpn != null) || (issuer != null) ) {
					distpoints.add(new DistributionPoint(dpn, null, issuer));            	            			
				}
			}
		}
		CRLDistPoint ret = null;
		if (!distpoints.isEmpty()) {
			ret = new CRLDistPoint((DistributionPoint[])distpoints.toArray(new DistributionPoint[distpoints.size()]));			
		} 
		if (ret == null) {
			log.error("DrlDistributionPoints missconfigured, no distribution points available.");
		}
		return ret;
	}	
}
