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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEREncodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.certextensions.CertificateExtensionException;
import org.ejbca.core.model.ca.certextensions.CertificateExtentionConfigurationException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ra.UserDataVO;

/** The Card Number is a PrintableString that shall respond to the number printed on a card on which the certificate is stored.
 * The extension is specified in the the Seis document SS 614331 chapter 4.3 and has OID 1.2.752.34.2.1 
 * 
 * CardNumber EXTENSION ::= {
 *       SYNTAX        CardNumber
 *       IDENTIFIED BY id-seis-pe-cn}
 *       -- id-seis-pe-cn is defined in Annex A
 * CardNumber ::= PrintableString 
 *
 * @version $Id$
 */
public class SeisCardNumber extends StandardCertificateExtension {

	private static final Logger log = Logger.getLogger(SeisCardNumber.class);

    /** OID for creating Smartcard Number Certificate Extension
     *  SEIS Cardnumber Extension according to SS 614330/31 */
    public static final String OID_CARDNUMBER = CertificateProfile.OID_CARDNUMBER;	//"1.2.752.34.2.1";

	/**
	 * @see StandardCertificateExtension#init(CertificateProfile)
	 */
	public void init(final CertificateProfile certProf) {
		super.setOID(SeisCardNumber.OID_CARDNUMBER);
		super.setCriticalFlag(false);
	}
	

	public DEREncodable getValue(final UserDataVO userData, final CA ca, final CertificateProfile certProfile, final PublicKey userPublicKey, final PublicKey caPublicKey)
			throws CertificateExtentionConfigurationException, CertificateExtensionException {
		final String cardnumber = userData.getCardNumber();
		DEREncodable ret = null;
		if (StringUtils.isNotEmpty(cardnumber)) {
			ret = new DERPrintableString(cardnumber);
			if (log.isDebugEnabled()) {
				log.debug("Seis card numer: "+cardnumber);
			}
		} else {
			if (log.isDebugEnabled()) {
				log.debug("Seis card numer is empty");
			}			
		}
		return ret;
	}

}
