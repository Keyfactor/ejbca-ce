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
package org.ejbca.ui.web.protocol;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.internal.CaCertificateCache;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificate.HashID;
import org.ejbca.config.VAConfiguration;

/**
 * Base class for servlets (CRL or Certificate) implementing rfc4378
 * 
 * @version  $Id$
 */
public abstract class StoreServletBase extends HttpServlet {

    private static final String SPACE = "|&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";
    
	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(StoreServletBase.class);

	protected CaCertificateCache certCache;
	
	@EJB
	private CertificateStoreSessionLocal certificateStoreSession;

	/**
	 * Called when the servlet is initialized.
	 * @param config see {@link HttpServlet#init(ServletConfig)}
	 * @throws ServletException
	 */
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.certCache = CaCertificateCache.INSTANCE;
	}

	/**
	 * Return certificate or CRL for the RFC4387 sHash http parameter
	 * @param sHash
	 * @param resp
	 * @param req
	 * @throws IOException
	 * @throws ServletException
	 */
	public abstract void sHash(String sHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	/**
	 * Return certificate or CRL for the RFC4387 iHash http parameter
	 * @param iHash
	 * @param resp
	 * @param req
	 * @throws IOException
	 * @throws ServletException
	 */
	public abstract void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	/**
	 * Return certificate or CRL for the RFC4387 sKIDHash http parameter
	 * @param sKIDHash
	 * @param resp
	 * @param req
	 * @throws IOException
	 * @throws ServletException
	 */
	public abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException;
	/**
	 * Return certificate or CRL for the RFC4387 sKIDHash http parameter. In this case the alias name has been used to get the parameter.
	 * @param sKIDHash
	 * @param resp
	 * @param req
	 * @param name alias name of the object
	 * @throws IOException
	 * @throws ServletException
	 */
	public abstract void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req, String name) throws IOException, ServletException;

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, java.io.IOException {
		if (log.isTraceEnabled()) {
			log.trace(">doGet()");			
		}
		try {
			if ( alias(req, resp) ) {
				return;
			}
			if ( reload(req, resp) ) {
				return;
			}
			if ( fromName(req, resp) ) {
				return;
			}
			rfcRequest(req, resp);
		} finally {
			if (log.isTraceEnabled()) {
				log.trace("<doGet()");			
			}
		}
	}
	private void rfcRequest(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
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
	private boolean alias(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final String alias = req.getParameter("setAlias");
		if ( alias==null ) {
			return false;
		}
		if ( !checkIfAutorizedIP(req, resp) ) {
			return true;
		}
		final int ix = alias.indexOf('=');
		if ( ix<1 || alias.length()<=ix+2 ) {
			log.debug("No valid alias definition string: "+alias);
			return true;
		}
		final String key = alias.substring(0, ix).trim();
		final String hash = alias.substring(ix+1).trim();
		if ( !VAConfiguration.sKIDHashSetAlias(key, hash) ) {
			log.error("Not possible to add: "+alias);
			return true;
		}
		log.debug("Alias '"+key+"' defined for hash '"+hash+"'.");
		return true;
	}
	private boolean fromName(HttpServletRequest req, HttpServletResponse resp) throws IOException, ServletException {
		final String alias = req.getParameter("alias");
		if ( alias==null ) {
			return false;
		}
		final String sKIDHash = VAConfiguration.sKIDHashFromName(alias);
		if ( sKIDHash==null || sKIDHash.length()<1 ) {
			final String m = "No '"+alias+"' alias defined in va.properties .";
			resp.sendError(HttpServletResponse.SC_NOT_FOUND, m);
			log.debug(m);
			return true;
		}
		sKIDHash( sKIDHash, resp, req, alias );
		return true;
	}
	private boolean reload(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		// We have a command to force reloading of the certificate cache that can only be run from localhost
		// http://localhost:8080/crls/search.cgi?reloadcache=true
		final boolean doReload = StringUtils.equals(req.getParameter("reloadcache"), "true");
		if ( !doReload ) {
			return false;
		}
		if ( !checkIfAutorizedIP(req, resp) ) {
			return true;
		}
		log.info("Reloading certificate and CRL caches due to request from "+req.getRemoteAddr());
		// Reload CA certificates
		certificateStoreSession.reloadCaCertificateCache();
		return true;
	}
	private boolean checkIfAutorizedIP(HttpServletRequest req, HttpServletResponse resp) throws IOException {
		final String remote = req.getRemoteAddr();
		// localhost in either ipv4 and ipv6
		if ( StringUtils.equals(remote, "127.0.0.1") || StringUtils.equals(remote, "0:0:0:0:0:0:0:1") ) {
			return true;
		}
		log.info("Got reloadcache command from unauthorized ip: "+remote);
		resp.sendError(HttpServletResponse.SC_UNAUTHORIZED);
		return false;
	}
	private void printInfo(X509Certificate certs[], String indent, PrintWriter pw, String url) {
		for ( int i=0; i<certs.length; i++ ) {
			printInfo(certs[i], indent, pw, url);
			pw.println();
			final X509Certificate issuedCerts[] = this.certCache.findLatestByIssuerDN(HashID.getFromSubjectDN(certs[i]));
			if ( issuedCerts==null || issuedCerts.length<1 ) {
				continue;
			}
			printInfo(issuedCerts, SPACE+indent, pw, url);
		}
	}
	
	/**
	 * Print info and download URL of a certificate or CRL.
	 * @param cert
	 * @param indent
	 * @param pw
	 * @param url
	 */
	public abstract void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url);
	/**
	 * @return the title of the page
	 */
	public abstract String getTitle();

	private void returnInfoPage(HttpServletResponse response, String info) throws IOException {
		response.setContentType("text/html");
		response.setCharacterEncoding("UTF-8");
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
		writer.flush();
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
		@Override
		public void println() {
			super.print("<br/>");
			super.println();
		}
		@Override
		public void println(String s) {
			super.print(s);
			println();
		}
	}
}
