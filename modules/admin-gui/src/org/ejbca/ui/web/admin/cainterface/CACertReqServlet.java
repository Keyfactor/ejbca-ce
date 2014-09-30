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
import java.security.cert.Certificate;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to handle certificate requests between CAs.<br>
 *
 * The servlet is called with method GET or POST and syntax
 * <code>cmd=&lt;command&gt;</code>.
 * <p>The following commands are supported:<br>
 * <ul>
 * <li>certreq - receives a certificate request</li>
 * <li>cert - sends a certificate</li>
 * <li>certpkcs7 - sends a certificate in pkcs7 format</li>
 * </ul>
 *
 * @version $Id$
 */
public class CACertReqServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CACertReqServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_PROPERTY_CAID = "caid";
    private static final String COMMAND_CERTREQ = "certreq";
	private static final String COMMAND_CERT           = "cert";    
	private static final String COMMAND_CERTPKCS7 = "certpkcs7";
    private static final String COMMAND_CERTLINK = "linkcert";
    private static final String FORMAT_PROPERTY_NAME = "format";

    @EJB
    private SignSessionLocal signSession;
    
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");

        // Check if authorized
        EjbcaWebBean ejbcawebbean = (EjbcaWebBean) req.getSession().getAttribute("ejbcawebbean");
        if ( ejbcawebbean == null ){
          try {
            ejbcawebbean = (EjbcaWebBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), EjbcaWebBean.class.getName());
           } catch (ClassNotFoundException exc) {
               throw new ServletException(exc.getMessage());
           }catch (Exception exc) {
               throw new ServletException (" Cannot create bean of class "+EjbcaWebBean.class.getName(), exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

		// Check if authorized
        CAInterfaceBean cabean = (CAInterfaceBean) req.getSession().getAttribute("cabean");
		if ( cabean == null ){
		  try {
			cabean = (CAInterfaceBean) java.beans.Beans.instantiate(Thread.currentThread().getContextClassLoader(), CAInterfaceBean.class.getName());
		   } catch (ClassNotFoundException exc) {
			   throw new ServletException(exc.getMessage());
		   }catch (Exception exc) {
			   throw new ServletException (" Cannot create bean of class "+CAInterfaceBean.class.getName(), exc);
		   }
		   req.getSession().setAttribute("cabean", cabean);
		}


        try{
          ejbcawebbean.initialize(req, StandardRules.ROLE_ROOT.resource());          
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }

		try{
		  cabean.initialize(ejbcawebbean);
		} catch(Exception e){
		   throw new java.io.IOException("Error initializing CACertReqServlet");
		}        
                
        
        // Keep this for logging.
        String remoteAddr = req.getRemoteAddr();
        RequestHelper.setDefaultCharacterEncoding(req);
        String command = req.getParameter(COMMAND_PROPERTY_NAME);
        String format = req.getParameter(FORMAT_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if (command.equalsIgnoreCase(COMMAND_CERTREQ)) {
            try {
            	byte[] request = cabean.getRequestData();
                String filename = null;
                CVCertificate cvccert = null;
                boolean isx509cert = false;
                try {
                    CVCObject parsedObject = CertificateParser.parseCVCObject(request);
                    // We will handle both the case if the request is an
                    // authenticated request, i.e. with an outer signature
                    // and when the request is missing the (optional) outer
                    // signature.
                    if (parsedObject instanceof CVCAuthenticatedRequest) {
                        CVCAuthenticatedRequest cvcreq = (CVCAuthenticatedRequest) parsedObject;
                        cvccert = cvcreq.getRequest();
                    } else {
                        cvccert = (CVCertificate) parsedObject;
                    }
                    HolderReferenceField chrf = cvccert.getCertificateBody().getHolderReference();
                    if (chrf != null) {
                    	filename = chrf.getConcatenated();
                    }
                } catch (ParseException ex) {
                    // Apparently it wasn't a CVC certificate, was it a certificate request?
                    try {
                        PKCS10RequestMessage p10 = RequestMessageUtils.genPKCS10RequestMessage(request);
                        filename = CertTools.getPartFromDN(p10.getRequestX500Name().toString(), "CN") + "_csr";
                    } catch (Exception e) { // NOPMD
                        // Nope, not a certificate request either, see if it was an X.509 certificate
                        Certificate cert = CertTools.getCertfromByteArray(request);
                        filename = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
                        if (filename == null) {
                            filename = "cert";
                        }
                        isx509cert = true;
                    }
                }

                int length = request.length;
                byte[] outbytes = request;
            	if (!StringUtils.equals(format, "binary")) {
            		String begin = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL;
            		String end = RequestHelper.END_CERTIFICATE_REQUEST_WITH_NL;
            		if (isx509cert) {
            			begin = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;
            			end = RequestHelper.END_CERTIFICATE_WITH_NL;
            		}
    				byte[] b64certreq = Base64.encode(request);
    				String out = begin;
    				out += new String(b64certreq);
    				out += end;
    				length = out.length();
                    filename += ".pem";
                    outbytes = out.getBytes();
                } else if (cvccert != null) {
                    filename += ".cvreq";
                } else {
                	if (isx509cert) {
                        filename += ".crt";                		
                	} else {
                        filename += ".req";                		
                	}
                }
            	
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename)+"\"");
                res.setContentType("application/octet-stream");
                res.setContentLength(length);
                res.getOutputStream().write(outbytes);
        		String iMsg = intres.getLocalizedMessage("certreq.sentlatestcertreq", remoteAddr);
                log.info(iMsg);
            } catch (Exception e) {
        		String errMsg = intres.getLocalizedMessage("certreq.errorsendlatestcertreq", remoteAddr);
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
                return;
            }
        }
		if (command.equalsIgnoreCase(COMMAND_CERT)) {
			 try {
			 	Certificate cert = cabean.getProcessedCertificate();
            	if (!StringUtils.equals(format, "binary")) {
    				byte[] b64cert = Base64.encode(cert.getEncoded());	
    				RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);							
            	} else {
            		RequestHelper.sendBinaryBytes(cert.getEncoded(), res, "application/octet-stream", "cert.crt");
            	}
			 } catch (Exception e) {
				 String errMsg = intres.getLocalizedMessage("certreq.errorsendcert", remoteAddr, e.getMessage());
                 log.error(errMsg, e);
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
				 return;
			 }
		 }
		if (command.equalsIgnoreCase(COMMAND_CERTPKCS7)) {
			 try {
				Certificate cert = cabean.getProcessedCertificate();		
		        byte[] pkcs7 = signSession.createPKCS7(ejbcawebbean.getAdminObject(), cert, true);							 	
			    byte[] b64cert = Base64.encode(pkcs7);	
			    RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_PKCS7_WITH_NL, RequestHelper.END_PKCS7_WITH_NL);																		 					
			 } catch (Exception e) {
				 String errMsg = intres.getLocalizedMessage("certreq.errorsendcert", remoteAddr, e.getMessage());
                 log.error(errMsg, e);
				 res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
				 return;
			 }
		 }
        if (command.equalsIgnoreCase(COMMAND_CERTLINK)) {
            try {
                final int caId = Integer.parseInt(req.getParameter(COMMAND_PROPERTY_CAID));
                final byte[] rawCert = cabean.getLinkCertificate(caId);
                if (rawCert!=null) {
                    if (!"binary".equals(format)) {
                        final byte[] b64cert = Base64.encode(rawCert);  
                        RequestHelper.sendNewB64Cert(b64cert, res, RequestHelper.BEGIN_CERTIFICATE_WITH_NL, RequestHelper.END_CERTIFICATE_WITH_NL);                         
                    } else {
                        RequestHelper.sendBinaryBytes(rawCert, res, "application/octet-stream", "cert.crt");
                    }
                }
            } catch (Exception e) {
                String errMsg = intres.getLocalizedMessage("certreq.errorsendcert", remoteAddr, e.getMessage());
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
                return;
            }
        }
    }
}
