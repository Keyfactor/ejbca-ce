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
package org.ejbca.core.protocol.ws.common;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

/**
 * Class used to generate a java.security.Certificate from a 
 * org.ejbca.core.protocol.ws.common.Certificate
 * 
 * @author Philip Vendil
 *
 * $id$
 */
public class CertificateHelper {

	
	public static java.security.cert.Certificate getCertificate(byte[] certificateData) throws CertificateException{
        CertificateFactory cf = CertTools.getCertificateFactory();
        java.security.cert.Certificate retval =  cf.generateCertificate(new ByteArrayInputStream(Base64.decode(certificateData)));
        return retval; 
	}
}
