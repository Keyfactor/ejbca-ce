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

import org.apache.log4j.Logger;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
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

    @EJB
    private CrlStoreSessionLocal crlStoreSession;

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean= (org.ejbca.ui.web.admin.configuration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), org.ejbca.ui.web.admin.configuration.EjbcaWebBean.class.getName());
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+ org.ejbca.ui.web.admin.configuration.EjbcaWebBean.class.getName(), exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

        try{
          ejbcawebbean.initialize(req, AccessRulesConstants.REGULAR_CABASICFUNCTIONS);
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerdn = null; 
        if(req.getParameter(ISSUER_PROPERTY) != null){
            // HttpServetRequets.getParameter URLDecodes the value for you
            // No need to do it manually, that will cause problems with + characters
            issuerdn = req.getParameter(ISSUER_PROPERTY);
            issuerdn = CertTools.stringToBCDNString(issuerdn);
        }
        
        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if (command.equalsIgnoreCase(COMMAND_CRL) && issuerdn != null) {
            try {
                byte[] crl = crlStoreSession.getLastCRL(issuerdn, false);
                String basename = getBaseFileName(issuerdn);
                String filename = basename+".crl";
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                res.setHeader("Content-disposition", "attachment; filename=\"" +  StringTools.stripFilename(filename) + "\"");
                res.setContentType("application/pkix-crl");
                res.setContentLength(crl.length);
                res.getOutputStream().write(crl);
                String iMsg = intres.getLocalizedMessage("certreq.sentlatestcrl", remoteAddr);
                log.info(iMsg);
            } catch (Exception e) {
                String errMsg = intres.getLocalizedMessage("certreq.errorsendcrl", remoteAddr, e.getMessage());
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
                return;
            }
        }
        if (command.equalsIgnoreCase(COMMAND_DELTACRL) && issuerdn != null) {
        	try {
        		byte[] crl = crlStoreSession.getLastCRL(issuerdn, true);
                String basename = getBaseFileName(issuerdn);
        		String filename = basename+"_delta.crl";
        		// We must remove cache headers for IE
        		ServletUtils.removeCacheHeaders(res);
        		res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename) + "\"");
        		res.setContentType("application/pkix-crl");
        		res.setContentLength(crl.length);
        		res.getOutputStream().write(crl);
        		log.info("Sent latest delta CRL to client at " + remoteAddr);
        	} catch (Exception e) {
        		log.error("Error sending latest delta CRL to " + remoteAddr, e);
        		res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting latest delta CRL.");
        		return;
        	}
        }
    } // doGet

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
		String basename = dnpart.replaceAll("\\W", "");
		return basename;
	}
}
