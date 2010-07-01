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

package org.ejbca.core.protocol.ocsp;

import java.security.cert.X509Certificate;
import java.util.Hashtable;

import javax.servlet.ServletConfig;
import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.ocsp.CertificateStatus;

/** Interface that must be implemented by OCSP extensions that are added to the OCSPServlet
 * 
 * @author tomas
 * @version $Id$
 * @see org.ejbca.ui.web.protocol.OCSPServlet
 *
 */
public interface IOCSPExtension {

	/** Called after construction
	 * 
	 * @param config ServletConfig that can be used to read init-params from web-xml
	 */
	public void init(ServletConfig config);
	
	/** Called by OCSP responder when the configured extension is found in the request.
	 * 
	 * @param request HttpServletRequest that can be used to find out information about caller, TLS certificate etc.
	 * @param cert X509Certificate the caller asked for in the OCSP request
	 * @return Hashtable with X509Extensions <String oid, X509Extension ext> that will be added to responseExtensions by OCSP responder, or null if an error occurs
	 */
	public Hashtable process(HttpServletRequest request, X509Certificate cert, CertificateStatus status);
	
	/** Returns the last error that occured during process(), when process returns null
	 * 
	 * @return error code as defined by implementing class
	 */
	public int getLastErrorCode();
}
