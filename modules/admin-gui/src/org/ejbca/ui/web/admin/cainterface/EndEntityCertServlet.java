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
import java.math.BigInteger;
import java.net.URLEncoder;
import java.security.cert.Certificate;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.pub.ServletUtils;


/**
 * Servlet used to distribute End Entity certificates through the "View Certificate" jsp page.
 * Checks that the administrator is authorized to view the user before sending the certificate<br>
 *
 * cert - returns certificate in PEM-format
 * nscert - returns certificate for Firefox
 * iecert - returns certificate for Internet Explorer
 *
 * cert, nscert and iecert also takes  parameters issuer and certificate sn were issuer is the DN of issuer and certificate serienumber 
 * is in hex format.
 *
 * @version $Id$
 */
public class EndEntityCertServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(EndEntityCertServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_NSCERT = "nscert";
    private static final String COMMAND_IECERT = "iecert";
    private static final String COMMAND_CERT = "cert";
   
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String CERTIFICATEDN_PROPERTY = "certificatesn";

    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doGet()");
        // Check if authorized
        EjbcaWebBean ejbcawebbean= (org.ejbca.ui.web.admin.configuration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        
        RAInterfaceBean rabean =  (org.ejbca.ui.web.admin.rainterface.RAInterfaceBean)
                                   req.getSession().getAttribute("rabean");
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
        
        if ( rabean == null ){
            try {
              rabean = (org.ejbca.ui.web.admin.rainterface.RAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), org.ejbca.ui.web.admin.rainterface.RAInterfaceBean.class.getName());
             } catch (ClassNotFoundException exc) {
                 throw new ServletException(exc.getMessage());
             }catch (Exception exc) {
                 throw new ServletException (" Cannot create bean of class "+ org.ejbca.ui.web.admin.rainterface.RAInterfaceBean.class.getName(), exc);
             }
             req.getSession().setAttribute("rabean", ejbcawebbean);
          }

        try{
          ejbcawebbean.initialize(req,AccessRulesConstants.REGULAR_VIEWCERTIFICATE);
          rabean.initialize(req,ejbcawebbean);                    
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }
        
        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerdn = req.getParameter(ISSUER_PROPERTY);        
        String certificatesn = req.getParameter(CERTIFICATEDN_PROPERTY);

        String command;
        // Keep this for logging.
        log.debug("Got request from "+req.getRemoteAddr());
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if ((command.equalsIgnoreCase(COMMAND_NSCERT) || command.equalsIgnoreCase(COMMAND_IECERT) || command.equalsIgnoreCase(COMMAND_CERT)) 
        	 && issuerdn != null && certificatesn != null) {
        	
        	BigInteger certsn = new BigInteger(certificatesn,16);
        	        	        
        	// Fetch the certificate and at the same time check that the user is authorized to it.
        	
        	try {
				rabean.loadCertificates(certsn, issuerdn);

				CertificateView certview = rabean.getCertificate(0);
				
				Certificate cert = certview.getCertificate();
				byte[] enccert = cert.getEncoded();
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
				if (command.equalsIgnoreCase(COMMAND_NSCERT)) {
					res.setContentType("application/x-x509-ca-cert");
					res.setContentLength(enccert.length);
					res.getOutputStream().write(enccert);
					log.debug("Sent CA cert to NS client, len="+enccert.length+".");
				} else if (command.equalsIgnoreCase(COMMAND_IECERT)) {
					res.setHeader("Content-disposition", "attachment; filename=" + URLEncoder.encode(certview.getUsername(),"UTF-8") + ".crt");
					res.setContentType("application/octet-stream");
					res.setContentLength(enccert.length);
					res.getOutputStream().write(enccert);
					log.debug("Sent CA cert to IE client, len="+enccert.length+".");
				} else if (command.equalsIgnoreCase(COMMAND_CERT)) {
					byte[] b64cert = Base64.encode(enccert);
					String out = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;                   
					out += new String(b64cert);
					out += RequestHelper.END_CERTIFICATE_WITH_NL;
					res.setHeader("Content-disposition", "attachment; filename=" + URLEncoder.encode(certview.getUsername(),"UTF-8") + ".pem");
					res.setContentType("application/octet-stream");
					res.setContentLength(out.length());
					res.getOutputStream().write(out.getBytes());
					log.debug("Sent CA cert to client, len="+out.length()+".");
				} else {
					res.setContentType("text/plain");
					res.getOutputStream().println("Commands="+COMMAND_NSCERT+" || "+COMMAND_IECERT+" || "+COMMAND_CERT);
					return;
				}
            } catch (Exception e) {
                log.error("Error getting certificates: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
                return;
            }
        }
        else {
            res.setContentType("text/plain");
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Request format");
            return;
        }
    } // doGet
}
