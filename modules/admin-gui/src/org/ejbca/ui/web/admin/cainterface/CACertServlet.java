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
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.cert.Certificate;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.StringTools;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet used to distribute CA certificates <br>
 *
 * cacert - returns ca certificate in PEM-format
 * nscacert - returns ca certificate for Firefox
 * iecacert - returns ca certificate for Internet Explorer
 *
 * cacert, nscacert and iecacert also takes optional parameter level=<int 1,2,...>, where the level is
 * which ca certificate in a hierachy should be returned. 0=root (default), 1=sub to root etc.
 *
 * @version $Id$
 */
public class CACertServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;
	private static final Logger log = Logger.getLogger(CACertServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_NSCACERT = "nscacert";
    private static final String COMMAND_IECACERT = "iecacert";
    private static final String COMMAND_CACERT = "cacert";
    private static final String COMMAND_JKSTRUSTSTORE = "jkscert";

    private static final String LEVEL_PROPERTY = "level";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String JKSPASSWORD_PROPERTY = "password";

    @EJB
    private SignSessionLocal signSession;

    public void init(ServletConfig config) throws ServletException {
        super.init(config);
    	if (signSession==null) {
    		log.error("Local EJB injection failed.");
    	}
    }
    
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
               throw new ServletException (" Cannot create bean of class "+org.ejbca.ui.web.admin.configuration.EjbcaWebBean.class.getName(), exc);
           }
           req.getSession().setAttribute("ejbcawebbean", ejbcawebbean);
        }

        try{
          ejbcawebbean.initialize(req,"/ca_functionality/basic_functions");
        } catch(Exception e){
           throw new java.io.IOException("Authorization Denied");
        }
        
        RequestHelper.setDefaultCharacterEncoding(req);

        // HttpServetRequets.getParameter URLDecodes the value for you
        // No need to do it manually, that will cause problems with + characters
        String issuerdn = req.getParameter(ISSUER_PROPERTY);
        issuerdn = CertTools.stringToBCDNString(issuerdn);

        String command;
        // Keep this for logging.
        log.debug("Got request from "+req.getRemoteAddr());
        command = req.getParameter(COMMAND_PROPERTY_NAME);
        if (command == null) {
            command = "";
        }
        if ((command.equalsIgnoreCase(COMMAND_NSCACERT) || command.equalsIgnoreCase(COMMAND_IECACERT) || command.equalsIgnoreCase(COMMAND_JKSTRUSTSTORE)
        		|| command.equalsIgnoreCase(COMMAND_CACERT)) && issuerdn != null ) {
            String lev = req.getParameter(LEVEL_PROPERTY);
            int level = 0;
            if (lev != null) {
                level = Integer.parseInt(lev);
            }
            // Root CA is level 0, next below root level 1 etc etc
            try {
                Certificate[] chain = (Certificate[]) signSession.getCertificateChain(issuerdn.hashCode()).toArray(new Certificate[0]);
                                                            
                // chain.length-1 is last cert in chain (root CA)
                if ( (chain.length-1-level) < 0 ) {
                    PrintStream ps = new PrintStream(res.getOutputStream());
                    ps.println("No CA certificate of level "+level+"exist.");
                    log.error("No CA certificate of level "+level+"exist.");
                    return;
                }
                Certificate cacert = (Certificate)chain[level];
                byte[] enccert = cacert.getEncoded();
                // Se if we can name the file as the CAs CN, if that does not exist try serialnumber, and if that does not exist, use the full O
                // and if that does not exist, use the fixed string CertificateAuthority. 
                String filename = RequestHelper.getFileNameFromCertNoEnding(cacert, "CertificateAuthority");
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
                    res.setContentType("application/x-x509-ca-cert");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to NS client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
                	String ending = ".cacert.crt";
                	if (cacert instanceof CardVerifiableCertificate) {
                		ending = ".cvcert";
                	}
                    res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename + ending) + "\"");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to IE client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
                    byte[] b64cert = Base64.encode(enccert);
                    String out = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;                   
                    out += new String(b64cert);
                    out += RequestHelper.END_CERTIFICATE_WITH_NL;
                    res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename + ".cacert.pem") + "\"");
                    res.setContentType("application/octet-stream");
                    res.setContentLength(out.length());
                    res.getOutputStream().write(out.getBytes());
                    log.debug("Sent CA cert to client, len="+out.length()+".");
                } else if (command.equalsIgnoreCase(COMMAND_JKSTRUSTSTORE)) {
                    String jksPassword = req.getParameter(JKSPASSWORD_PROPERTY).trim();
                    int passwordRequiredLength = 6;
                    if ( jksPassword != null && jksPassword.length() >= passwordRequiredLength ) {
                    	KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
                    	ks.load(null, jksPassword.toCharArray());
                    	ks.setCertificateEntry(filename, cacert);
                        res.setHeader("Content-disposition", "attachment; filename=\"" + StringTools.stripFilename(filename + ".cacert.jks") + "\"");
                        res.setContentType("application/octet-stream");
                    	ks.store(res.getOutputStream(), jksPassword.toCharArray());
                    } else {
                        res.setContentType("text/plain");
                        res.getOutputStream().println(COMMAND_JKSTRUSTSTORE + " requires " + JKSPASSWORD_PROPERTY +
                        		" with a minimum of " + passwordRequiredLength+ " chars to be set");
                        return;
                    }
                } else {
                    res.setContentType("text/plain");
                    res.getOutputStream().println("Commands="+COMMAND_NSCACERT+" || "+COMMAND_IECACERT+" || "+COMMAND_CACERT+" || "+COMMAND_JKSTRUSTSTORE);
                    return;
                }
            } catch (Exception e) {
                log.error("Error getting CA certificates: ", e);
                res.sendError(HttpServletResponse.SC_NOT_FOUND, "Error getting CA certificates.");
                return;
            }
        }
        else {
            res.sendError(HttpServletResponse.SC_BAD_REQUEST, "Bad Request format");
            return;
        }
    } // doGet
}
