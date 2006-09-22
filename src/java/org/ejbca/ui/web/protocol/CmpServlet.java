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

package org.ejbca.ui.web.protocol;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcher;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;
import org.ejbca.util.Base64;


/**
 * Servlet implementing server side of the Certificate Management Protocols (CMP) 
 *
 * @author tomas
 * @version $Id: CmpServlet.java,v 1.2 2006-09-22 14:56:11 anatom Exp $
 * 
 * @web.servlet name = "CmpServlet"
 *              display-name = "CmpServlet"
 *              description="Used to handle CMP (RFC4210) protocol messages"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/cmp"
 * 
 * @web.env-entry description="Allow the client/RA to specify that the CA should not verify POP"
 *   name="allowRaVerifyPopo"
 *   type="java.lang.String"
 *   value="1"
 *   
 * @web.env-entry description="Enforce a particual CA instead of taking it from the request"
 *   name="defaultCA"
 *   type="java.lang.String"
 *   value=""
 *   
 * @web.env-entry description="Defines which component from the DN should be used as username in EJBCA. Can be cN, UID or nothing. Nothing means that the DN will be used to look up the user."
 *   name="extractUsernameComponent"
 *   type="java.lang.String"
 *   value=""
 *   
 * @web.ejb-local-ref
 *  name="ejb/SignSessionLocal"
 *  type="Session"
 *  link="RSASignSession"
 *  home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/UserAdminSessionLocal"
 *  type="Session"
 *  link="UserAdminSession"
 *  home="org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome"
 *  local="org.ejbca.core.ejb.ra.IUserAdminSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/CAAdminSessionLocal"
 *  type="Session"
 *  link="CAAdminSession"
 *  home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *  
 */
public class CmpServlet extends HttpServlet {
	private static Logger log = Logger.getLogger(CmpServlet.class);
	
	private boolean allowRaVerifyPopo = true;
	private String defaultCA = null;
	private String extractUsernameComponent = null;
	
	/**
	 * Inits the CMP servlet
	 *
	 * @param config servlet configuration
	 *
	 * @throws ServletException on error during initialization
	 */
	public void init(ServletConfig config) throws ServletException {
		super.init(config);		
		
		if (StringUtils.equals("0", getInitParameter("allowRaVerifyPopo"))) {
			allowRaVerifyPopo = false;
		}
		String str = getInitParameter("defaultCA");
		if (StringUtils.isNotEmpty(str)) {
			defaultCA = str;
		}
		str = getInitParameter("extractUsernameComponent"); 
		if (StringUtils.isNotEmpty(str)) {
			extractUsernameComponent = str;
		}
	}
	
	/**
	 * Handles HTTP post
	 *
	 * @param request java standard arg
	 * @param response java standard arg
	 *
	 * @throws IOException input/output error
	 * @throws ServletException if the post could not be handled
	 */
	public void doPost(HttpServletRequest request, HttpServletResponse response)
	throws IOException, ServletException {
		log.debug(">doPost()");
		/* 
		 POST
		 <binary CMP message>
		 */
		ServletInputStream sin = request.getInputStream();
		// This small code snippet is inspired/copied from apache IO utils by Tomas Gustavsson...
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		byte[] buf = new byte[1024];
		int n = 0;
		while (-1 != (n = sin.read(buf))) {
			output.write(buf, 0, n);
		}
		service(output.toByteArray(), request.getRemoteAddr(), response);
		log.debug("<doPost()");
	} //doPost
	
	/**
	 * Handles HTTP get
	 *
	 * @param request java standard arg
	 * @param response java standard arg
	 *
	 * @throws IOException input/output error
	 * @throws ServletException if the post could not be handled
	 */
	public void doGet(HttpServletRequest request, HttpServletResponse response)
	throws java.io.IOException, ServletException {
		log.debug(">doGet()");
		
		log.info("Received not allowed method GET in CMP servlet: query string=" + request.getQueryString());
		response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
		
		log.debug("<doGet()");
	} // doGet
	
	private void service(byte[] message, String remoteAddr, HttpServletResponse response) throws IOException {
		try {
			if ((message == null)) {
				log.error("Got request missing message.");
				response.sendError(HttpServletResponse.SC_BAD_REQUEST,
				"A message must be supplied!");
				return;
			}
			
			Admin administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);
			if (log.isDebugEnabled()) {
				log.debug("Message: " + new String(Base64.encode(message)));
			}
			
			CmpMessageDispatcher dispatcher = new CmpMessageDispatcher(administrator);
			dispatcher.setAllowRaVerifyPopo(allowRaVerifyPopo);
			dispatcher.setDefaultCA(defaultCA);
			dispatcher.setExtractUsernameComponent(extractUsernameComponent);
			byte[] resp = dispatcher.dispatch(message);
			if (resp == null) {
				// unknown error?
				log.error("CMP message dispatcher returned a null response!");
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Null response");
				return;
			}
			// Add no-cache headers as defined in draft-ietf-pkix-cmp-transport-protocols-05.txt
			ServletUtils.addCacheHeaders(response);
			// Send back CMP response
			RequestHelper.sendBinaryBytes(resp, response, "application/pkixcmp");
		} catch (Exception e) {
			log.error("Error in CmpServlet:", e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}
	
} // ScepServlet
