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
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.ejbca.core.protocol.certificatestore.CertificateCacheFactory;
import org.ejbca.core.protocol.certificatestore.HashID;
import org.ejbca.core.protocol.certificatestore.ICertificateCache;

/**
 * @author Lars Silven PrimeKey
 * @version  $Id$
 */
public abstract class StoreServletBase extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(StoreServletBase.class);

	protected ICertificateCache certCache;
	final String space = "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

	public void init(ServletConfig config, CertificateStoreSessionLocal certificateStoreSession) throws ServletException {
		super.init(config);
		this.certCache = CertificateCacheFactory.getInstance(certificateStoreSession);
	}

	abstract void sHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	abstract void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;

	/* (non-Javadoc)
	 * @see javax.servlet.http.HttpServlet#doGet(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, java.io.IOException {
		if (log.isTraceEnabled()) {
			log.trace(">doGet()");			
		}
		// We have a command to force reloading of the certificate cache that can only be run from localhost
		// http://localhost:8080/crls/search.cgi?reloadcache=true
		final boolean doReload = StringUtils.equals(req.getParameter("reloadcache"), "true");
		if ( doReload ) {
			final String remote = req.getRemoteAddr();
			// localhost in either ipv4 and ipv6
			if (StringUtils.equals(remote, "127.0.0.1") || (StringUtils.equals(remote, "0:0:0:0:0:0:0:1"))) {
				log.info("Reloading certificate and CRL caches due to request from "+remote);
				// Reload CA certificates
				certCache.forceReload();
			} else {
				log.info("Got reloadcache command from unauthorized ip: "+remote);
				resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
			}
		} else {
			// Do actual processing of the protocol
			{
				final String sHash = req.getParameter(RFC4387URL.sHash.toString());
				if ( sHash!=null ) {
					sHash( sHash, resp, req );
					return;
				}
			}{
				final String iHash = req.getParameter(RFC4387URL.iHash.toString());
				if ( iHash!=null ) {
					iHash( iHash, resp, req );
					return;
				}
			}{
				final String sKIDHash = req.getParameter(RFC4387URL.sKIDHash.toString());
				if ( sKIDHash!=null ) {
					sKIDHash(sKIDHash, resp, req );
					return;
				}
			}
			printInfo(req, resp);
		}
		if (log.isTraceEnabled()) {
			log.trace("<doGet()");			
		}
	}
	private void printInfo(X509Certificate certs[], String indent, PrintWriter pw, String url) {
		for ( int i=0; i<certs.length; i++ ) {
			printInfo(certs[i], indent, pw, url);
			pw.println();
			final X509Certificate issuedCerts[] = this.certCache.findLatestByIssuerDN(HashID.getFromSubjectDN(certs[i]));
			if ( issuedCerts==null || issuedCerts.length<1 ) {
				continue;
			}
			printInfo(issuedCerts, this.space+indent, pw, url);
		}
	}

	abstract void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url);
	abstract String getTitle();

	private void returnInfoPage(HttpServletResponse response, String info) throws IOException {
		response.setContentType("text/html");
		final PrintWriter writer = response.getWriter();

		writer.println("<html>");
		writer.println("<head>");
		writer.println("<title>"+getTitle()+"</title>");
		writer.println("</head>");
		writer.println("<body>");

		writer.println("<table border=\"0\">");
		writer.println("<tr>");
		writer.println("<td>");
		writer.println("<h1>"+getTitle()+"</h1>");
		writer.println("<p>When searching for certificates you can use iHash, sHash and sKIDHash. iHash is the ASN1 encoded DN of the issuer in a certificate, sHash of the subject and sKIDHash is the subjectKeyIdentifier. If you search with it you get all certificates that has the same issuer, except for the root certificate. You do not find a root certificate if you search with the iHash of the root. It has been assumed that sHash should be used when searching for a root.</p>");
		writer.println("<p>When searching for CRLs you can use iHash and sKIDHash. iHash is the ASN1 encoded DN of the issuer in a certificate and sKIDHash is the subjectKeyIdentifier.</p>");
		writer.println("<hr>");
		writer.println(info);
		writer.println("</td>");
		writer.println("</tr>");
		writer.println("</table>");

		writer.println("</body>");
		writer.println("</html>");
	}
	private void printInfo(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final StringWriter sw = new StringWriter();
		final PrintWriter pw = new HtmlPrintWriter(sw);
		printInfo(this.certCache.getRootCertificates(), "", pw, req.getRequestURL().toString());
		pw.flush();
		pw.close();
		sw.flush();
		returnInfoPage(resp, sw.toString());
		sw.close();
	}

	private class HtmlPrintWriter extends PrintWriter {

		public HtmlPrintWriter(Writer out) {
			super(out);
		}

		public void println() {
			super.print("<br/>");
			super.println();
		}

		public void println(String s) {
			super.print(s);
			println();
		}
	}
}
