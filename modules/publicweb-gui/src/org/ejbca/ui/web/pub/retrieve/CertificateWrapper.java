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
 
package org.ejbca.ui.web.pub.retrieve;

import java.security.cert.Certificate;

import org.cesecore.util.CertTools;

/**
 * This bean wraps a certificate, to be able to use CertTools to get values from certs, 
 * instead of the direct X509Certificate methods. It's not certain that this is an X509Certificate.
 * 
 * To make it easy to use from JSTL pages, most methods take no arguments.
 * The arguments are supplied as member variables instead. <br>
 * 
 * @author Tomas Gustavsson
 * @version $Id$
 */
public class CertificateWrapper {
	
	private Certificate mCurrentCert;


	/**
	 * default constructor.
	 */
	public CertificateWrapper(Certificate cert) {
		mCurrentCert = cert;
	}

	public String getIssuerDN() {
		return CertTools.getIssuerDN(mCurrentCert);
	}

	public String getSubjectDN() {
		return CertTools.getSubjectDN(mCurrentCert);
	}

}
