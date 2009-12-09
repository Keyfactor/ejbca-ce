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
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.IOException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;
import org.ejbca.util.CertTools;

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
 * 
 * @web.servlet name = "GetCRL"
 *              display-name = "GetCRLServlet"
 *              description="Used to retrive CA certificate request and Processed CA Certificates from AdminWeb GUI"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/ca/getcrl/getcrl"
 *
 */
public class GetCRLServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(GetCRLServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CRL = "crl";
    private static final String COMMAND_DELTACRL = "deltacrl";
    private static final String ISSUER_PROPERTY = "issuer";

    private ICertificateStoreSessionLocalHome storehome = null;

    private synchronized ICertificateStoreSessionLocalHome getStoreHome() throws IOException {
        try{
            if(storehome == null){
              storehome = (ICertificateStoreSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
            }
          } catch(Exception e){
             throw new java.io.IOException("Authorization Denied");
          }
          return storehome;
    }
      

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean= (org.ejbca.ui.web.admin.configuration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), org.ejbca.ui.web.admin.configuration.EjbcaWebBean.class.getName());
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+ org.ejbca.ui.web.admin.configuration.EjbcaWebBean.class.getName(), exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

        try{
          ejbcawebbean.initialize(req, "/ca_functionality/basic_functions");
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerdn = null; 
        if(req.getParameter(ISSUER_PROPERTY) != null){
          issuerdn = java.net.URLDecoder.decode(req.getParameter(ISSUER_PROPERTY),"UTF-8");
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
                Admin admin = ejbcawebbean.getAdminObject();
                ICertificateStoreSessionLocal store = getStoreHome().create();
                byte[] crl = store.getLastCRL(admin, issuerdn, false);
                X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
                String dn = CertTools.getIssuerDN(x509crl);
                String filename = CertTools.getPartFromDN(dn,"CN")+".crl";
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
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
        		Admin admin = ejbcawebbean.getAdminObject();
        		ICertificateStoreSessionLocal store = getStoreHome().create();
        		byte[] crl = store.getLastCRL(admin, issuerdn, true);
        		X509CRL x509crl = CertTools.getCRLfromByteArray(crl);
        		String dn = CertTools.getIssuerDN(x509crl);
        		String filename = "delta_" + CertTools.getPartFromDN(dn,"CN")+".crl";
        		// We must remove cache headers for IE
        		ServletUtils.removeCacheHeaders(res);
        		res.setHeader("Content-disposition", "attachment; filename=" +  filename);
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

}
