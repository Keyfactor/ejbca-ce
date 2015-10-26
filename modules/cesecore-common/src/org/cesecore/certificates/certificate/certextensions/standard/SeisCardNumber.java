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

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERPrintableString;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.internal.CertificateValidity;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;

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

	private static final long serialVersionUID = 1L;

    private static final Logger log = Logger.getLogger(SeisCardNumber.class);

    /** OID for creating Smartcard Number Certificate Extension
     *  SEIS Cardnumber Extension according to SS 614330/31 */
    public static final String OID_CARDNUMBER = CertificateProfile.OID_CARDNUMBER;	//"1.2.752.34.2.1";

    @Override
	public void init(final CertificateProfile certProf) {
		super.setOID(SeisCardNumber.OID_CARDNUMBER);
		super.setCriticalFlag(false);
	}
	
    @Override
    public ASN1Encodable getValue(final EndEntityInformation userData, final CA ca, final CertificateProfile certProfile,
            final PublicKey userPublicKey, final PublicKey caPublicKey, CertificateValidity val) {
		final String cardnumber = userData.getCardNumber();
		ASN1Encodable ret = null;
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
