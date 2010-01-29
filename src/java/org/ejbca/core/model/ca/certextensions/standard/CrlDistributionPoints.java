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
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
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
	 * Constructor for creating the certificate extension 
	 */
	public CrlDistributionPoints() {
		super();
	}

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(CertificateProfile certProf) {
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
	public DEREncodable getValue(UserDataVO subject, CA ca, CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey ) throws CertificateExtentionConfigurationException, CertificateExtensionException {
		String crldistpoint = certProfile.getCRLDistributionPointURI();
		String crlissuer=certProfile.getCRLIssuer();
		X509CA x509ca = (X509CA)ca;
		if(certProfile.getUseDefaultCRLDistributionPoint()){
			crldistpoint = x509ca.getDefaultCRLDistPoint();
			crlissuer = x509ca.getDefaultCRLIssuer();
		}
		// Multiple CDPs are separated with the ';' sign        	         	 
		ArrayList dpns = new ArrayList();
		if (StringUtils.isNotEmpty(crldistpoint)) {
			Iterator/*String*/ it = CrlDistributionPoints.splitURIs(crldistpoint).iterator();
			while (it.hasNext()) {
				// 6 is URI
				String uri = (String) it.next();
				GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
				log.debug("Added CRL distpoint: "+uri);
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				GeneralNames gns = new GeneralNames(new DERSequence(vec));
				DistributionPointName dpn = new DistributionPointName(0, gns);
				dpns.add(dpn);
			}            	
		}
		// CRL issuer works much like Dist point URI. If separated by ; it is put in the same global distPoint as the URI, 
		// if there is more of one of them, the one with more is put in an own global distPoint.
		ArrayList issuers = new ArrayList();
		if (StringUtils.isNotEmpty(crlissuer)) {
			StringTokenizer tokenizer = new StringTokenizer(crlissuer, ";", false);
			while (tokenizer.hasMoreTokens()) {
				String issuer = tokenizer.nextToken();
				GeneralName gn = new GeneralName(new X509Name(issuer));
				log.debug("Added CRL issuer: "+issuer);
				ASN1EncodableVector vec = new ASN1EncodableVector();
				vec.add(gn);
				GeneralNames gns = new GeneralNames(new DERSequence(vec));
				issuers.add(gns);
			}            	
		}
		ArrayList distpoints = new ArrayList();
		if ( (issuers.size() > 0) || (dpns.size() > 0) ) {
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
		if (distpoints.size() > 0) {
			ret = new CRLDistPoint((DistributionPoint[])distpoints.toArray(new DistributionPoint[0]));			
		} 
		if (ret == null) {
			log.error("DrlDistributionPoints missconfigured, no distribution points available.");
		}
		return ret;
	}
	
	/**
	 * Splits a string with semicolon separated and optionally double-quoted 
	 * strings into a collection of strings.
	 * <p>
	 * Strings that contains semicolon has to be quoted.
	 * Unbalanced quotes (the end quote is missing) is handled as if there 
	 * was a quote at the end of the string.
	 * <pre>
	 * Examples:
	 * splitURIs("a;b;c") =&gt; [a, b, c]
	 * splitURIs("a;\"b;c\";d") =&gt; [a, b;c, d]
	 * splitURIs("a;\"b;c;d") =&gt; [a, b;c;d]
	 * </pre>
	 * <p>
	 * See org.ejbca.core.model.ca.certextensions.TestCertificateExtensionManager#test03TestSplitURIs() 
	 * for more examples.
	 * @param dispPoints The semicolon separated string and which optionally 
	 * uses double-quotes
	 * @return A collection of strings
	 */
	public static Collection/*String*/ splitURIs(String dispPoints) {

        LinkedList/*String*/ result = new LinkedList/*String*/();

        dispPoints = dispPoints.trim();
        
        for(int i = 0; i < dispPoints.length(); i++) {
            int nextQ = dispPoints.indexOf('"', i);
            if(nextQ == i) {
                nextQ = dispPoints.indexOf('"', i+1);
                if(nextQ == -1) {
                    nextQ = dispPoints.length(); // unbalanced so eat(the rest)
                }
                // eat(to quote)
                result.add(dispPoints.substring(i+1, nextQ).trim());
                i = nextQ;
            } else {
                int nextSep = dispPoints.indexOf(';', i);
                if(nextSep != i) {   
	                if(nextSep != -1) { // eat(to sep)
	                    result.add(dispPoints.substring(i, nextSep).trim());
	                    i = nextSep;
	                } else if (i < dispPoints.length()) { // eat(the rest)
	                    result.add(dispPoints.substring(i).trim());
	                    break;
	                }
                } // Else skip
            }
        }
        return result;
    }
}
