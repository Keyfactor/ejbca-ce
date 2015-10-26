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
import java.util.StringTokenizer;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
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

/** 
 * 
 * Class for standard X509 certificate extension. 
 * See rfc3280 or later for spec of this extension.      
 * 
 * @version $Id$
 */
public class FreshestCrl extends StandardCertificateExtension {
    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(FreshestCrl.class);
	
    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(Extension.freshestCRL.getId());
		super.setCriticalFlag(false);
	}
    
    @Override
    public ASN1Encodable getValue(final EndEntityInformation subject, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) throws
            CertificateExtensionException {
        String freshestcrldistpoint = certProfile.getFreshestCRLURI();
        final X509CA x509ca = (X509CA)ca;
        if(certProfile.getUseCADefinedFreshestCRL()){
            freshestcrldistpoint = x509ca.getCADefinedFreshestCRL();
        }
        // Multiple FCDPs are separated with the ';' sign
        CRLDistPoint ret = null;
        if (freshestcrldistpoint != null) {
        	final StringTokenizer tokenizer = new StringTokenizer(freshestcrldistpoint, ";", false);
        	final ArrayList<DistributionPoint> distpoints = new ArrayList<DistributionPoint>();
            while (tokenizer.hasMoreTokens()) {
            	final String uri = tokenizer.nextToken();
                final GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uri));
                if (log.isDebugEnabled()) {
                	log.debug("Added freshest CRL distpoint: "+uri);
                }
                final ASN1EncodableVector vec = new ASN1EncodableVector();
                vec.add(gn);
                final GeneralNames gns = GeneralNames.getInstance(new DERSequence(vec));
                final DistributionPointName dpn = new DistributionPointName(0, gns);
                distpoints.add(new DistributionPoint(dpn, null, null));
            }
            if (!distpoints.isEmpty()) {
                ret = new CRLDistPoint((DistributionPoint[])distpoints.toArray(new DistributionPoint[distpoints.size()]));
            }            	 
        } 
		if (ret == null) {
	       	 log.error("UseFreshestCRL is true, but no URI string defined!");
		}
		return ret;
	}	
}
