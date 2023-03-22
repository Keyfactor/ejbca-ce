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
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.bean.SessionBeans;
import org.ejbca.ui.web.admin.rainterface.RAInterfaceBean;
import org.ejbca.ui.web.pub.ServletUtils;

import com.keyfactor.util.CertTools;


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
public class EndEntityCertServlet extends BaseAdminServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(EndEntityCertServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_NSCERT = "nscert";
    private static final String COMMAND_IECERT = "iecert";
    private static final String COMMAND_CERT = "cert";
   
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String CERTIFICATESN_PROPERTY = "certificatesn";

    @Override
    public void doPost(HttpServletRequest req, HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doPost()");
        doGet(req, res);
        log.trace("<doPost()");
    }

    @Override
    public void doGet(HttpServletRequest req,  HttpServletResponse res) throws IOException, ServletException {
        log.trace(">doGet()");
        RequestHelper.setDefaultCharacterEncoding(req);
        String issuerdn = req.getParameter(ISSUER_PROPERTY);        
        String certificatesn = req.getParameter(CERTIFICATESN_PROPERTY);

        String command;
        // Keep this for logging.
        log.debug("Got request from "+req.getRemoteAddr());
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if ((command.equalsIgnoreCase(COMMAND_NSCERT) || command.equalsIgnoreCase(COMMAND_IECERT) || command.equalsIgnoreCase(COMMAND_CERT)) 
        	 && issuerdn != null && certificatesn != null) {
        	
            BigInteger certsn = CertTools.getSerialNumberFromString(certificatesn);
        	        	        
        	// Fetch the certificate and at the same time check that the user is authorized to it.
        	
        	try {
        	    final RAInterfaceBean raBean = SessionBeans.getRaBean(req);
				raBean.loadCertificates(certsn, issuerdn);
				CertificateView certview = raBean.getCertificate(0);
				if (certview == null) {
				    throw new NotFoundException("No certificate exists with issuerDN '" + issuerdn + "', serial " + certsn.toString(16));
				}
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
					String out = CertTools.getPemFromCertificate(cert);
					res.setHeader("Content-disposition", "attachment; filename=" + URLEncoder.encode(certview.getUsername(),"UTF-8") + ".pem");
					res.setContentType("application/octet-stream");
					res.setContentLength(out.length());
					res.getOutputStream().write(out.getBytes());
					log.debug("Sent CA cert to client, len="+out.length()+".");
				} else {
					res.setContentType("text/plain");
					res.getOutputStream().println("Commands="+COMMAND_NSCERT+" || "+COMMAND_IECERT+" || "+COMMAND_CERT);
				}
            } catch (Exception e) {
                log.info("Error getting certificates: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting certificates.");
            }
        } else {
            res.setContentType("text/plain");
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Request format");
        }
    } // doGet
}
