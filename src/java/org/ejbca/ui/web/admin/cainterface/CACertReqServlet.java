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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.cert.Certificate;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.protocol.ExtendedPKCS10CertificationRequest;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.RequestHelper;
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
 * @version $Id: CACertReqServlet.java,v 1.1 2006-01-17 20:28:08 anatom Exp $
 * 
 * @web.servlet name = "CACertReq"
 *              display-name = "CACertReqServlet"
 *              description="Used to retrive CA certificate request and Processed CA Certificates from AdminWeb GUI"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/ca/editcas/cacertreq"
 *
 */
public class CACertReqServlet extends HttpServlet {

    private static Logger log = Logger.getLogger(CACertReqServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_CERTREQ = "certreq";
	private static final String COMMAND_CERT           = "cert";    
	private static final String COMMAND_CERTPKCS7 = "certpkcs7";
	
	private ISignSessionLocal signsession = null;
   
   private synchronized ISignSessionLocal getSignSession(){
   	  if(signsession == null){	
		try {
		    ISignSessionLocalHome signhome = (ISignSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
		    signsession = signhome.create();
		}catch(Exception e){
			throw new EJBException(e);      	  	    	  	
		}
   	  }
   	  return signsession;
   }
   
   
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        try {


        } catch( Exception e ) {
            throw new ServletException(e);
        }
    }

    public void doPost(HttpServletRequest req, HttpServletResponse res)
        throws IOException, ServletException {
        log.debug(">doPost()");
        doGet(req, res);
        log.debug("<doPost()");
    } //doPost

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.debug(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean= (org.ejbca.ui.web.admin.configuration.EjbcaWebBean)
                                   req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (org.ejbca.ui.web.admin.configuration.EjbcaWebBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), "org.ejbca.ui.web.admin.configuration.EjbcaWebBean");
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+"org.ejbca.ui.web.admin.configuration.EjbcaWebBean", exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

		// Check if authorized
		CAInterfaceBean cabean= (org.ejbca.ui.web.admin.cainterface.CAInterfaceBean)
								   req.getSession().getAttribute("cabean");
		if ( cabean == null ){
		  try {
			cabean = (org.ejbca.ui.web.admin.cainterface.CAInterfaceBean) java.beans.Beans.instantiate(this.getClass().getClassLoader(), "org.ejbca.ui.web.admin.cainterface.CAInterfaceBean");
		   } catch (ClassNotFoundException exc) {
			   throw new ServletException(exc.getMessage());
		   }catch (Exception exc) {
			   throw new ServletException (" Cannot create bean of class "+"org.ejbca.ui.web.admin.cainterface.CAInterfaceBean", exc);
		   }
		   req.getSession().setAttribute("cabean", cabean);
		}


        try{
          ejbcawebbean.initialize(req, "/super_administrator");          
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

		try{
		  cabean.initialize(req, ejbcawebbean);
		} catch(Exception e){
		   throw new java.io.IOException("Error initializing CACertReqServlet");
		}        
                
        
        String command;
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null)
            command = "";
        if (command.equalsIgnoreCase(COMMAND_CERTREQ)) {
            try {
                
            	ExtendedPKCS10CertificationRequest pkcs10request = cabean.getPKCS10RequestData();
				ByteArrayOutputStream bOut = new ByteArrayOutputStream();
				DEROutputStream dOut = new DEROutputStream(bOut);
				dOut.writeObject(pkcs10request);
				dOut.close();								          
				byte[] b64certreq = org.ejbca.util.Base64.encode(bOut.toByteArray());
				String out = "-----BEGIN CERTIFICATE REQUEST-----\n";
				out += new String(b64certreq);
				out += "\n-----END CERTIFICATE REQUEST-----\n";
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                String filename = "pkcs10certificaterequest.pem";
                res.setHeader("Content-disposition", "attachment; filename=" +  filename);
                res.setContentType("application/octet-stream");
                res.setContentLength(out.length());
                res.getOutputStream().write(out.getBytes());
                log.info("Sent latest Certificate Request to client at " + remoteAddr);
            } catch (Exception e) {
                log.error("Error sending Certificate Request to " + remoteAddr, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error sending Certificate Request.");
                return;
            }
        }
		if (command.equalsIgnoreCase(COMMAND_CERT)) {
			 try {
			 	Certificate cert = cabean.getProcessedCertificate();			 	
				byte[] b64cert = org.ejbca.util.Base64.encode(cert.getEncoded());	
				RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);							
			 } catch (Exception e) {
                 log.error("Error sending processed certificate to " + remoteAddr, e);
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting processed certificate.");
				 return;
			 }
		 }
		if (command.equalsIgnoreCase(COMMAND_CERTPKCS7)) {
			 try {
				Certificate cert = cabean.getProcessedCertificate();		
		        byte[] pkcs7 =  getSignSession().createPKCS7(ejbcawebbean.getAdminObject(), cert, true);							 	
			    byte[] b64cert = org.ejbca.util.Base64.encode(pkcs7);	
			    RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);																		 					
			 } catch (Exception e) {
                 log.error("Error sending processed certificate to " + remoteAddr, e);
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting processed certificate.");
				 return;
			 }
		 }




    } // doGet

}
