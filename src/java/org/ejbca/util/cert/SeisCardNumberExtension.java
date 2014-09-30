/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.util.cert;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERPrintableString;
import org.cesecore.certificates.certificate.certextensions.standard.SeisCardNumber;
import org.cesecore.util.CertTools;

/**
 * A class for reading values from SeisCardNumber extension.
 *
 * @author  Tomas Gustavsson
 * @version $Id$
 */
public class SeisCardNumberExtension extends CertTools {

    private static Logger log = Logger.getLogger(SeisCardNumberExtension.class);
    
    /**
     * inhibits creation of new SubjectDirAttrExtension
     */
    private SeisCardNumberExtension() {
    }

    /**
     * CardNumber EXTENSION ::= {
     *       SYNTAX        CardNumber
     *       IDENTIFIED BY id-seis-pe-cn}
     *       -- id-seis-pe-cn is defined in Annex A
     * CardNumber ::= PrintableString 	 *
     * 
	 * @param certificate containing card number
	 * @return String containing card number. 
	 * @throws java.lang.Exception
	 */
	public static String getSeisCardNumber(Certificate certificate) throws Exception {
		log.debug("Search for CardNumber");
        String ret = null;
        if (certificate instanceof X509Certificate) {
			X509Certificate x509cert = (X509Certificate) certificate;
	        ASN1Primitive obj = CertTools.getExtensionValue(x509cert, SeisCardNumber.OID_CARDNUMBER);
	        if (obj == null) {
	            return null;
	        }
	        DERPrintableString number = (DERPrintableString)obj;
	        ret = number.getString();
        }
        return ret;            
	}

}
