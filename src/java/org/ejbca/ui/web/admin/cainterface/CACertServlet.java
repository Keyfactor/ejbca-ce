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
import java.io.PrintStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import javax.ejb.EJBException;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.model.log.Admin;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.pub.ServletUtils;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;

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
 *
 * @web.servlet name = "CACert"
 *              display-name = "CACertServlet"
 *              description="Returns the specified CA certificate"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/ca/cacert"
 *
 * We put all ejb-env-entrys in this servlet, this is a collection of all envs for all servlets and jsps
 * 
 * @web.env-entry description="Defines the admin directory"
 *   name="ADMINDIRECTORY"
 *   type="java.lang.String"
 *   value="adminweb"
 * 
 * @web.env-entry description="Defines the available themes by css-filenames separated with a comma"
 *   name="AVAILABLETHEMES"
 *   type="java.lang.String"
 *   value="default_theme.css,second_theme.css"
 * 
 * @web.env-entry description="Protocol used by EJBCA public webcomponents. i.e that doesn't require client authentication"
 *   name="PUBLICPROTOCOL"
 *   type="java.lang.String"
 *   value="http"
 * 
 * @web.env-entry description="Protocol used by EJBCA private webcomponents. i.e that requires client authentication"
 *   name="PRIVATEPROTOCOL"
 *   type="java.lang.String"
 *   value="https"
 * 
 * We put all ejb-local-refs in this servlet, this is a collection of all refs for all servlets and jsps
 * 
 * @web.ejb-local-ref
 *  name="ejb/RSASignSessionLocal"
 *  type="Session"
 *  link="RSASignSession"
 *  home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreSessionLocal"
 *  type="Session"
 *  link="CertificateStoreSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 * 
 * @web.ejb-local-ref
 *  name="ejb/CAAdminSessionLocal"
 *  type="Session"
 *  link="CAAdminSession"
 *  home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/UserAdminSessionLocal"
 *  type="Session"
 *  link="UserAdminSession"
 *  home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *  local="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/RaAdminSessionLocal"
 *  type="Session"
 *  link="RaAdminSession"
 *  home="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome"
 *  local="org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/LogSessionLocal"
 *  type="Session"
 *  link="LogSession"
 *  home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *  local="org.ejbca.core.ejb.log.ILogSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/AuthorizationSessionLocal"
 *  type="Session"
 *  link="AuthorizationSession"
 *  home="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome"
 *  local="org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/HardTokenSessionLocal"
 *  type="Session"
 *  link="HardTokenSession"
 *  home="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome"
 *  local="org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/HardTokenBatchJobSessionLocal"
 *  type="Session"
 *  link="HardTokenBatchJobSession"
 *  home="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionLocalHome"
 *  local="org.ejbca.core.ejb.hardtoken.IHardTokenBatchJobSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/KeyRecoverySessionLocal"
 *  type="Session"
 *  link="KeyRecoverySession"
 *  home="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome"
 *  local="org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/PublisherSessionLocal"
 *  type="Session"
 *  link="PublisherSession"
 *  home="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/UserDataSourceSessionLocal"
 *  type="Session"
 *  link="UserDataSourceSession"
 *  home="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocalHome"
 *  local="org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal"  
 *  
 * @web.ejb-local-ref
 *  name="ejb/ApprovalSessionLocal"
 *  type="Session"
 *  link="ApprovalSession"
 *  home="org.ejbca.core.ejb.approval.IApprovalSessionLocalHome"
 *  local="org.ejbca.core.ejb.approval.IApprovalSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/ServiceSessionLocal"
 *  type="Session"
 *  link="ServiceSession"
 *  home="org.ejbca.core.ejb.services.IServiceSessionLocalHome"
 *  local="org.ejbca.core.ejb.services.IServiceSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/ServiceTimerSessionLocal"
 *  type="Session"
 *  link="ServiceTimerSession"
 *  home="org.ejbca.core.ejb.services.IServiceTimerSessionLocalHome"
 *  local="org.ejbca.core.ejb.services.IServiceTimerSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/PublisherQueueSessionLocal"
 *  type="Session"
 *  link="PublisherQueueSession"
 *  home="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/CreateCRLSessionLocal"
 *  type="Session"
 *  link="CreateCRLSession"
 *  home="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *  
 * @web.resource-ref
 *  name="${datasource.jndi-name-prefix}${datasource.jndi-name}"
 *  type="javax.sql.DataSource"
 *  auth="Container"
 */
public class CACertServlet extends HttpServlet {

    private static final Logger log = Logger.getLogger(CACertServlet.class);

    private static final String COMMAND_PROPERTY_NAME = "cmd";
    private static final String COMMAND_NSCACERT = "nscacert";
    private static final String COMMAND_IECACERT = "iecacert";
    private static final String COMMAND_CACERT = "cacert";
    private static final String COMMAND_JKSTRUSTSTORE = "jkscert";

    private static final String LEVEL_PROPERTY = "level";
    private static final String ISSUER_PROPERTY = "issuer";
    private static final String JKSPASSWORD_PROPERTY = "password";

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

        String issuerdn = req.getParameter(ISSUER_PROPERTY);
        
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
                ISignSessionLocal ss = getSignSession();
                Admin admin = ejbcawebbean.getAdminObject();
                Certificate[] chain = (Certificate[]) ss.getCertificateChain(admin, issuerdn.hashCode()).toArray(new Certificate[0]);
                                                            
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
                String dnpart = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                if (dnpart == null) {
                	dnpart = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "SN");
                }
                if (dnpart == null) {
                	dnpart = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "O");
                }
                if (dnpart == null) {
                	dnpart = "CertificateAuthority";
                }
                // Strip whitespace though
            	String strippedCACN = dnpart.replaceAll("\\W", "");
                // We must remove cache headers for IE
                ServletUtils.removeCacheHeaders(res);
                if (command.equalsIgnoreCase(COMMAND_NSCACERT)) {
                    res.setContentType("application/x-x509-ca-cert");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to NS client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_IECACERT)) {
                	String ending = "crt";
                	if (cacert instanceof CardVerifiableCertificate) {
                		ending = "cvcert";
                	}
                    res.setHeader("Content-disposition", "attachment; filename=" + strippedCACN + ".cacert."+ending);
                    res.setContentType("application/octet-stream");
                    res.setContentLength(enccert.length);
                    res.getOutputStream().write(enccert);
                    log.debug("Sent CA cert to IE client, len="+enccert.length+".");
                } else if (command.equalsIgnoreCase(COMMAND_CACERT)) {
                    byte[] b64cert = Base64.encode(enccert);
                    String out = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;                   
                    out += new String(b64cert);
                    out += RequestHelper.END_CERTIFICATE_WITH_NL;
                    res.setHeader("Content-disposition", "attachment; filename=" + strippedCACN + ".cacert.pem");
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
                    	ks.setCertificateEntry(strippedCACN, cacert);
                        res.setHeader("Content-disposition", "attachment; filename=" + strippedCACN + ".cacert.jks");
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
