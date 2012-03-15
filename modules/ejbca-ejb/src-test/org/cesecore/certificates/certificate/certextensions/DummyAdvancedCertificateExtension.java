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

package org.cesecore.certificates.certificate.certextensions;

import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

/**
 * Dummy advanced certificate extension, used for demonstration
 * and testing of the certificate extension framework.
 * 
 * Should implement the getValue method.
 * 
 * 
 * Based on EJBCA version: DummyAdvancedCertificateExtension.java 8597 2010-01-29 11:01:30Z anatom
 * 
 * @version $Id$
 */
public class DummyAdvancedCertificateExtension extends CertificateExtension {

    private static String PROPERTY_VALUE = "value";

	/**
	 * The main method that should return a ASN1Encodable
	 * using the input data (optional) or defined properties (optional)
	 * 
	 */	
	public ASN1Encodable getValue(EndEntityInformation userData, CA ca,
			CertificateProfile certProfile, PublicKey userPublicKey, PublicKey caPublicKey) throws CertificateExtensionException {
		
		String value = getProperties().getProperty(PROPERTY_VALUE);
		
		return new DERPrintableString(value);
	}

}
