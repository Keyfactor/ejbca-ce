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
import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.HashID;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.ejbca.core.protocol.crlstore.CRLCache;
import org.ejbca.util.HTMLTools;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

/** 
 * Servlet implementing server side of the CRL Store.
 * For a detailed description see RFC 4387.
 * Addition to RFC 4387 is the ability to specify delta CRL with the parameter "delta="
 * Addition to RFC 4387 is the ability to specify download of a specific CRL by crlNumber with the parameter "crlnumber=<number>"
 * Addition to RFC 4387 is the ability to specify a CRL partition number with the parameter "partition=<number>"
 * 
 * 
 */
public class CRLStoreServlet extends StoreServletBase {

	private static final long serialVersionUID = 1L;

	private static final Logger log = Logger.getLogger(CRLStoreServlet.class);
	
	private static final String PARAM_DELTACRL = "delta";
	private static final String PARAM_CRLNUMBER = "crlnumber";
	private static final String PARAM_PARTITION = "partition";

	@EJB
	private CrlStoreSessionLocal crlStoreSession;
	
	private CRLCache crlCache;

	@Override
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
		this.crlCache = CRLCache.getInstance(crlStoreSession, certCache);		
	}

	@Override
	public void sHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		// do nothing for CRLs
	}

	@Override
	public void iHash(String iHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
	    final int crlPartitionIndex = getCrlPartitionIndex(req);
	    final byte[] crlBytes = crlCache.findByIssuerDN(HashID.getFromB64(iHash), crlPartitionIndex, isDelta(req), getCrlNumber(req));
		returnCrl(crlBytes, resp, iHash, crlPartitionIndex, isDelta(req));
	}

	@Override
	public void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req) throws IOException, ServletException {
		sKIDHash( sKIDHash, resp, req, sKIDHash);
	}

	@Override
	public void sKIDHash(String sKIDHash, HttpServletResponse resp, HttpServletRequest req, String name) throws IOException, ServletException {
	    final int crlPartitionIndex = getCrlPartitionIndex(req);
	    final byte[] crlBytes = crlCache.findBySubjectKeyIdentifier(HashID.getFromB64(sKIDHash), crlPartitionIndex, isDelta(req), getCrlNumber(req));
		returnCrl(crlBytes, resp, name, crlPartitionIndex, isDelta(req));
	}

	@Override
	public void printInfo(X509Certificate cert, String indent, PrintWriter pw, String url) {
        // Important to escape output that have an even small chance of coming from untrusted source
		pw.println(indent+HTMLTools.htmlescape(cert.getSubjectX500Principal().toString()));
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert)));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert)));
		pw.println(indent+" "+RFC4387URL.iHash.getRef(url, HashID.getFromSubjectDN(cert), true));
		pw.println(indent+" "+RFC4387URL.sKIDHash.getRef(url, HashID.getFromKeyID(cert), true));
	}

	@Override
	public String getTitle() {
		return "CRLs";
	}

	private boolean isDelta(final HttpServletRequest req) {
		return req.getParameterMap().get(PARAM_DELTACRL)!=null;
	}

	private int getCrlNumber(final HttpServletRequest req) {
	    final String crlNumber = req.getParameter(PARAM_CRLNUMBER);
        if (StringUtils.isNumeric(crlNumber) && (Integer.valueOf(crlNumber) >= 0) ) {
            return Integer.valueOf(crlNumber);
        }
        return -1;
	}
	
	private int getCrlPartitionIndex(final HttpServletRequest req) {
        final String partition = req.getParameter(PARAM_PARTITION);
        if (StringUtils.isNumeric(partition) && (Integer.valueOf(partition) >= 0) ) {
            return Integer.valueOf(partition);
        }
        return CertificateConstants.NO_CRL_PARTITION;
    }

	private void returnCrl(final byte[] crl, HttpServletResponse resp, String name, final int crlPartitionIndex, boolean isDelta) throws IOException {
		if (ArrayUtils.isEmpty(crl)) {
		    if (log.isDebugEnabled()) {
		        log.debug("CRL was not found. Hash=" + name + ", DeltaCRL=" + isDelta + ", Partition=" + crlPartitionIndex);
		    }
			resp.sendError(HttpServletResponse.SC_NO_CONTENT, "No CRL with hash: "+HTMLTools.htmlescape(name));
			return;
		}
		resp.setContentType("application/pkix-crl");
		resp.setHeader("Content-disposition", "attachment; filename=\"" + 
		        (isDelta?"delta":"") +
		        StringTools.stripFilename(name) +
		        (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION ? "_partition" + crlPartitionIndex : "") +
		        ".crl\"");
		resp.setContentLength(crl.length);
		resp.getOutputStream().write(crl);
	}
	
    protected void printInfo(X509Certificate[] certs, String indent, PrintWriter pw, String url) {
        for (X509Certificate cert : certs) {
            //Verify that there is a CRL to download
            if (crlStoreSession.crlExistsForCa(CertTools.getSubjectDN(cert))) {
                // Escape the URL as it might be unsafe
                printInfo(cert, indent, pw, HTMLTools.htmlescape(url));
                pw.println();
            }
            final X509Certificate[] issuedCerts = this.certCache.findLatestByIssuerDN(HashID.getFromSubjectDN(cert));
            if (ArrayUtils.isEmpty(issuedCerts)) {
                continue;
            }
            printInfo(issuedCerts, SPACE + indent, pw, url);
        }
    }
}
