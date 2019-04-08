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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBeanImpl;
import org.ejbca.ui.web.jsf.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to distribute  CRLs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>command=&lt;command&gt;</code>.
 * <p>The follwing commands are supported:<br>
 * <ul>
 * <li>crl - gets the latest CRL.
 *
 * @version $Id$
 */
public class GetCRLServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(GetCRLServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String COMMAND_DELTACRL = "deltacrl";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String PARTITION_PROPERTY = "partition";

    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    @Override
    public void doGet(final HttpServletRequest req,  final HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean = (EjbcaWebBean) req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (EjbcaWebBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), EjbcaWebBeanImpl.class.getName());
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage(), exc);
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+ EjbcaWebBeanImpl.class.getName(), exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

        try {
            ejbcawebbean.initialize(req, AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
        } catch (Exception e) {
            final String fullMsg = "Access denied to " + AccessRulesConstants.REGULAR_VIEWCERTIFICATE + " for client " + req.getRemoteAddr();
            if (log.isDebugEnabled()) {
                log.warn(fullMsg, e);
            } else {
                log.warn(fullMsg);
            }
            res.sendError(HttpServletResponse.SC_FORBIDDEN, "Authorization denied");
            return;
        }

        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerDn = req.getParameter(ISSUER_PROPERTY);
        if (issuerDn == null) {
            log.warn("Missing 'issuer' parameter from client " + req.getRemoteAddr());
            res.sendError(HttpServletResponse.SC_NOT_FOUND, "Missing 'issuer' parameter.");
            return;
        }
        issuerDn = CertTools.stringToBCDNString(issuerDn);
        final String partitionString = req.getParameter(PARTITION_PROPERTY);
        final int crlPartitionIndex = StringUtils.isNotBlank(partitionString) ? Integer.valueOf(partitionString) : CertificateConstants.NO_CRL_PARTITION;
        final String command = StringUtils.defaultString(req.getParameter(COMMAND_PROPERTY_NAME));

        if (command.equalsIgnoreCase(COMMAND_CRL) && issuerDn != null) {
            sendLatestCrl(req, res, issuerDn, crlPartitionIndex, false);
        } else if (command.equalsIgnoreCase(COMMAND_DELTACRL) && issuerDn != null) {
            sendLatestCrl(req, res, issuerDn, crlPartitionIndex, true);
        }
        log.trace("<doGet()");
    } // doGet

    private void sendLatestCrl(final HttpServletRequest req, final HttpServletResponse res, final String issuerDn, final int crlPartitionIndex, final boolean deltaCrl) throws IOException {
        // Keep this for logging.
        final String remoteAddr = req.getRemoteAddr();
        try {
            final byte[] crl = crlStoreSession.getLastCRL(issuerDn, crlPartitionIndex, false);
            if (crl == null) {
                String errMsg = intres.getLocalizedMessage("certreq.errorsendcrl", remoteAddr, "CRL does not exist for CA");
                log.info(errMsg);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
                return;
            }
            final StringBuilder sb = new StringBuilder();
            sb.append(getBaseFileName(issuerDn));
            if (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION) {
                sb.append("_partition" + crlPartitionIndex);
            }
            if (deltaCrl) {
                sb.append("_delta");
            }
            sb.append(".crl");
            final String filename = sb.toString();
            // We must remove cache headers for IE
            ServletUtils.removeCacheHeaders(res);
            res.setHeader("Content-disposition", "attachment; filename=\"" +  StringTools.stripFilename(filename) + "\"");
            res.setContentType("application/pkix-crl");
            res.setContentLength(crl.length);
            res.getOutputStream().write(crl);
            final String infoMsg = intres.getLocalizedMessage(deltaCrl ? "certreq.sentlatestdeltacrl" : "certreq.sentlatestcrl", remoteAddr);
            log.info(infoMsg);
        } catch (Exception e) {
            final String errMsg = intres.getLocalizedMessage(deltaCrl ? "certreq.errorsenddeltacrl" : "certreq.errorsendcrl", remoteAddr, e.getMessage());
            log.error(errMsg, e);
            res.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, errMsg);
            return;
        }
    }

	/**
	 * @param dn
	 * @return base filename, without extension, with CN, or SN (of CN is null) or O, with spaces removed so name is compacted.
	 */
	private String getBaseFileName(String dn) {
		String dnpart = CertTools.getPartFromDN(dn, "CN");
		if (dnpart == null) {
			dnpart = CertTools.getPartFromDN(dn, "SN");
		}
		if (dnpart == null) {
			dnpart = CertTools.getPartFromDN(dn, "O");
		}
		return dnpart.replaceAll("\\W", "");
	}
}
