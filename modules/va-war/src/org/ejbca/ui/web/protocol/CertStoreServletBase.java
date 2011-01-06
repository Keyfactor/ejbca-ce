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
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.InternetHeaders;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMultipart;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertStore;
import org.ejbca.util.CertTools;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
class CertStoreServletBase extends StoreServletBase {
	private final static Logger log = Logger.getLogger(CertStoreServletBase.class);
	/**
	 * Sets the object to get certificates from.
	 */
	CertStoreServletBase( ICertStore certStore ) {
		super(certStore);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#iHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCerts( this.certCache.findLatestByIssuerDN(HashID.getFromB64(iHash)), resp, iHash );
		return;
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sKIDHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		returnCert( this.certCache.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash)), resp, sKIDHash );
		return;
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#sHash(java.lang.String, javax.servlet.http.HttpServletResponse)
	 */
	void sHash(String sHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		final X509Certificate cert = this.certCache.findLatestBySubjectDN(HashID.getFromB64(sHash));
		returnCert( cert, resp, sHash);
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#printInfo(java.security.cert.X509Certificate, java.lang.String, java.io.PrintWriter, java.lang.String)
	 */
	void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
		pw.println(indent+cert.getSubjectX500Principal());
		pw.println(indent+" "+RFC4387URL.sHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
	}
	/* (non-Javadoc)
	 * @see org.ejbca.ui.web.protocol.StoreServletBase#getTitle()
	 */
	String getTitle() {
		return "CA certificates";
	}
	private void returnCert(X509Certificate cert, HttpServletResponse resp, String name) throws IOException, ServletException {
		if (cert==null) {
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No certificate with hash: "+name);
			return;
		}
		final byte encoded[];
		try {
			encoded = cert.getEncoded();
		} catch (CertificateEncodingException e) {
			throw new ServletException(e);
		}
		resp.setContentType("application/pkix-cert");
		resp.setHeader("Content-disposition", "attachment; filename=cert" + name + ".der");
		resp.setContentLength(encoded.length);
		resp.getOutputStream().write(encoded);
	}
	private void returnCerts(X509Certificate certs[], HttpServletResponse resp, String name) throws IOException, ServletException {
		if (certs==null) {
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No certificates with issuer hash DN: "+name);
			return;
		}
		final Multipart mp = new MimeMultipart();// mixed is default
		try {
			resp.setContentType(mp.getContentType());
			for( int i=0; i<certs.length; i++ ) {
				final String filename = "cert" + name + '-' + i + ".der";
				if (log.isDebugEnabled()) {
					log.debug("Returning certificate with issuerDN '"+CertTools.getIssuerDN(certs[i])+"' and subjectDN '"+CertTools.getSubjectDN(certs[i])+"'. Filename="+filename);
				}
				final InternetHeaders headers = new InternetHeaders();
				headers.addHeader("Content-type", "application/pkix-cert");
				headers.addHeader("Content-disposition", "attachment; filename="+filename);
				mp.addBodyPart(new MimeBodyPart(headers,certs[i].getEncoded()));
			}
			if (log.isTraceEnabled()) {
				log.trace("content type: "+mp.getContentType());				
			}
			mp.writeTo(resp.getOutputStream());
			resp.flushBuffer();
		} catch (CertificateEncodingException e) {
			throw new ServletException(e);
		} catch (MessagingException e) {
			throw new ServletException(e);
		}/* old implementation that works.
		final String BOUNDARY = "BOUNDARY";
		resp.setContentType("multipart/mixed; boundary=\""+BOUNDARY+'"');
		final PrintStream ps = new PrintStream(resp.getOutputStream());
		ps.println("This is a multi-part message in MIME format.");
		for( int i=0; i<certs.length; i++ ) {
			// Upload the certificates with mime-header for user certificates.
			ps.println("--"+BOUNDARY);
			ps.println("Content-type: application/pkix-cert");
			ps.println("Content-disposition: attachment; filename=cert" + name + '-' + i + ".der");
			ps.println();
			try {
				ps.write(certs[i].getEncoded());
			} catch (CertificateEncodingException e) {
				throw new ServletException(e);
			}
			ps.println();
		}
		// ready
		ps.println("--"+BOUNDARY+"--");
		ps.flush();*/
	}
}
