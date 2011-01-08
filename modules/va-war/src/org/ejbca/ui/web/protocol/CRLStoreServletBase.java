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

package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertStore;
import org.ejbca.core.protocol.crlstore.CRLCacheFactory;
import org.ejbca.core.protocol.crlstore.ICRLCache;
import org.ejbca.core.protocol.crlstore.ICRLStore;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CRLStoreServletBase extends StoreServletBase {
	private ICRLCache crlCache;
	private final ICRLStore crlStore;
	/**
	 * Sets the object to get certificates from.
	 */
	CRLStoreServletBase( ICertStore certStore, ICRLStore crlStore ) {
		super(certStore);
		this.crlStore = crlStore;
	}
	
	/* (non-Javadoc)
	 * @see javax.servlet.GenericServlet#init(javax.servlet.ServletConfig)
	 */
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.crlCache = CRLCacheFactory.getInstance(crlStore, this.certCache);		
	}

	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		// do nothing for CRLs
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#iHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCrl( this.crlCache.findLatestByIssuerDN(HashID.getFromB64(iHash), isDelta(req)), resp, iHash, isDelta(req) );		
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sKIDHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCrl( this.crlCache.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash), isDelta(req)), resp, sKIDHash, isDelta(req) );
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#printInfo(java.security.cert.X509Certificate, java.lang.String, java.io.PrintWriter, java.lang.String)
	 */
	void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
		pw.println(indent+cert.getSubjectX500Principal());
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert), true));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert), true));
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#getTitle()
	 */
	String getTitle() {
		return "CRLs";
	}
	private boolean isDelta(HttpServletRequest req) {
		return req.getParameterMap().get("delta")!=null;
	}
	private void returnCrl( byte crl[], HttpServletResponse resp, String name, boolean isDelta ) throws IOException {
		if ( crl==null || crl.length<1 ) {
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No CRL with hash: "+name);
			return;
		}
		resp.setContentType("application/pkix-crl");
		resp.setHeader("Content-disposition", "attachment; filename="+(isDelta?"delta":"")+"crl" + name + ".der");
		resp.setContentLength(crl.length);
		resp.getOutputStream().write(crl);
	}
}
