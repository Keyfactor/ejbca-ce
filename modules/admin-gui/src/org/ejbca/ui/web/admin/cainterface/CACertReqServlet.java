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
import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.cvc.CVCAuthenticatedRequest;
import org.ejbca.cvc.CVCObject;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CertificateParser;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ParseException;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.pub.ServletUtils;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.StringTools;

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
public class CACertReqServlet extends BaseAdminServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CACertReqServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_PROPERTY_CAID = "caid";
    private static final String COMMAND_PROPERTY_CATYPE = "caType";
    private static final String COMMAND_CERTREQ = "certreq";
	private static final String COMMAND_CERT           = "cert";    
	private static final String COMMAND_CERTPKCS7 = "certpkcs7";
    private static final String COMMAND_CERTLINK = "linkcert";
    private static final String FORMAT_PROPERTY_NAME = "format";
    
    private static final String COMMAND_ITS_ECA_CSR = "itsecacsr";
    private static final String PARAM_CA_NAME = "caname";

    @EJB
    private CAAdminSessionLocal caAdminSession;
    @EJB
    private SignSessionLocal signSession;
    @EJB
    private CaSessionLocal caSession;
    
    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws java.io.IOException, ServletException {
        log.trace(">doGet()");
        final AuthenticationToken admin = getAuthenticationToken(req);
        final CAInterfaceBean caBean = SessionBeans.getCaBean(req);

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
            	byte[] request = caBean.getRequestData();
            	log.info("current request: " + org.apache.commons.codec.binary.Base64.encodeBase64String(request));                
            	String filename = null;
                CVCertificate cvccert = null;
                boolean isx509cert = false;
                final int caType = Integer.parseInt(req.getParameter(COMMAND_PROPERTY_CATYPE));
                if(caType != CAInfo.CATYPE_CITS) {
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
                            String subjectDN = p10.getRequestDN();
                            isAuthorizedToCABySubjectDN(caBean, subjectDN);
                        } catch (AuthorizationDeniedException e) {
                            throw e;
                        } catch (Exception e) { // NOPMD
                            // Nope, not a certificate request either, see if it was an X.509 certificate
                            Certificate cert = CertTools.getCertfromByteArray(request, Certificate.class);
                            filename = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
                            if (filename == null) {
                                filename = "cert";
                            }
                            isx509cert = true;
                        }
                    }
                }
                int length = request.length;
                byte[] outbytes = request;
            	if (!StringUtils.equals(format, "binary")) {
            		String begin = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL;
            		String end = RequestHelper.END_CERTIFICATE_REQUEST_WITH_NL;
            		if (isx509cert) {
            			begin = CertTools.BEGIN_CERTIFICATE_WITH_NL;
            			end = CertTools.END_CERTIFICATE_WITH_NL;
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
            } catch (AuthorizationDeniedException e) {
                String errMsg = intres.getLocalizedMessage("certreq.authorizationdenied", remoteAddr);
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_UNAUTHORIZED, errMsg);
                return;
            } catch (Exception e) {
        		String errMsg = intres.getLocalizedMessage("certreq.errorsendlatestcertreq", remoteAddr);
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
                return;
            }
        }
		if (command.equalsIgnoreCase(COMMAND_CERT)) {
			 try {
			 	Certificate cert = caBean.getProcessedCertificate();
            	if (!StringUtils.equals(format, "binary")) {
    				byte[] b64cert = Base64.encode(cert.getEncoded());	
    				RequestHelper.sendNewB64Cert(b64cert, res, CertTools.BEGIN_CERTIFICATE_WITH_NL, CertTools.END_CERTIFICATE_WITH_NL);
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
			     X509Certificate cert = (X509Certificate) caBean.getProcessedCertificate();
		        byte[] pkcs7 = signSession.createPKCS7(admin, cert, true);							 	
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
                final byte[] rawCert = caAdminSession.getLatestLinkCertificate(caId);
                if (rawCert!=null) {
                    if (!"binary".equals(format)) {
                        final byte[] b64cert = Base64.encode(rawCert);  
                        RequestHelper.sendNewB64Cert(b64cert, res, CertTools.BEGIN_CERTIFICATE_WITH_NL, CertTools.END_CERTIFICATE_WITH_NL);
                    } else {
                        RequestHelper.sendBinaryBytes(rawCert, res, "application/octet-stream", "cert.crt");
                    }
                }
            } catch (Exception e) {
                String errMsg = intres.getLocalizedMessage("certreq.errorsendcert", remoteAddr, e.getMessage());
                log.error(errMsg, e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, errMsg);
            }
        }
        if (command.equalsIgnoreCase(COMMAND_ITS_ECA_CSR)) {
            byte[] request = caBean.getRequestData();
            String filename = null;
            int length = request.length;
            byte[] outbytes = request;
            String caname = req.getParameter(PARAM_CA_NAME);
            
            filename = caname + "_csr.oer";
            // We must remove cache headers for IE
            ServletUtils.removeCacheHeaders(res);
            res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename)+"\"");
            res.setContentType("application/octet-stream");
            res.setContentLength(length);
            res.getOutputStream().write(outbytes);
            String iMsg = intres.getLocalizedMessage("certreq.sentlatestcertreq", remoteAddr);
            log.info(iMsg);
        }
    }

    private void isAuthorizedToCABySubjectDN(CAInterfaceBean caBean, String subjectDN) throws AuthorizationDeniedException {
        final String bcdn = CertTools.stringToBCDNString(subjectDN);
        final CAData cadata = caSession.findBySubjectDN(bcdn);
        if (cadata != null) {
            boolean authorized = caSession.authorizedToCA(caBean.getAuthenticationToken(), cadata.getCaId());
            if (!authorized) {
                final String msg = intres.getLocalizedMessage("caadmin.notauthorizedtoca", caBean.getAuthenticationToken().toString(), cadata.getCaId());
                throw new AuthorizationDeniedException(msg);
            }
        } else {
            throw new AuthorizationDeniedException("CA can not be found: " + subjectDN);                
        }
    }
}
