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
import java.util.ArrayList;
import java.util.Iterator;
import java.util.StringTokenizer;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.StringTools;

/** 
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @version $Id$
 */
public class CrlDistributionPoints extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(CrlDistributionPoints.class);
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.cRLDistributionPoints.getId());
		super.setCriticalFlag(certProf.getCRLDistributionPointCritical());
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws
            CertificateExtensionException {
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
				final GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
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
				final GeneralName gn = new GeneralName(new X500Name(issuer));
				if (log.isDebugEnabled()) {
					log.debug("Added CRL issuer: "+issuer);
				}
				final ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				final GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
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
