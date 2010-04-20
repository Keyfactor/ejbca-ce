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

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERObject;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.IResponseMessage;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcher;
import org.ejbca.ui.web.LimitLengthASN1Reader;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.pub.ServletUtils;

/**
 * Servlet implementing server side of the Certificate Management Protocols (CMP) 
 *
 * @author tomas
 * @version $Id$
 * 
 * @web.servlet name = "CmpServlet"
 *              display-name = "CmpServlet"
 *              description="Used to handle CMP (RFC4210) protocol messages"
 *              load-on-startup = "99"
 *
 * @web.servlet-mapping url-pattern = "/cmp"
 * 
 * @web.env-entry description="Allow the client/RA to specify that the CA should not verify POP, set to true to allow no POP (raVerify in the rfc). Default false."
 *   name="allowRaVerifyPopo"
 *   type="java.lang.String"
 *   value="${cmp.allowraverifypopo}"
 *   
 * @web.env-entry description="Enforce a particual CA instead of taking it from the request. Default empty."
 *   name="defaultCA"
 *   type="java.lang.String"
 *   value="${cmp.defaultca}"
 *   
 * @web.env-entry description="Defines which component from the DN should be used to look up username in EJBCA. Can be CN, UID or nothing. Nothing means that the DN will be used to look up the user. Default empty."
 *   name="extractUsernameComponent"
 *   type="java.lang.String"
 *   value="${cmp.extractusernamecomponent}"
 *   
 * @web.env-entry description="If the CMP service should work in 'normal' or 'ra' mode (see docs). Default normal (or empty value means the same)."
 *   name="operationMode"
 *   type="java.lang.String"
 *   value="${cmp.operationmode}"
 *   
 * @web.env-entry description="Which sort of protection the response messages will have. Default signature."
 *   name="responseProtection"
 *   type="java.lang.String"
 *   value="${cmp.responseprotection}"
 *   
 * @web.env-entry description="Shared secret between the CA and the RA used to authenticate valid RA messages. Default empty."
 *   name="raAuthenticationSecret"
 *   type="java.lang.String"
 *   value="${cmp.ra.authenticationsecret}"
 *   
 * @web.env-entry description="Which generation scheme should be used, RANDOM or DN. Default DN."
 *   name="raModeNameGenerationScheme"
 *   type="java.lang.String"
 *   value="${cmp.ra.namegenerationscheme}"
 *   
 * @web.env-entry description="Parameters for name generation, for DN it can be CN or UID. Default CN."
 *   name="raModeNameGenerationParameters"
 *   type="java.lang.String"
 *   value="${cmp.ra.namegenerationparameters}"
 *   
 * @web.env-entry description="Prefix to generated name, a string that can contain the markup ${RANDOM} to inser random chars. Default empty."
 *   name="raModeNameGenerationPrefix"
 *   type="java.lang.String"
 *   value="${cmp.ra.namegenerationprefix}"
 *   
 * @web.env-entry description="Postfix to generated name, a string that can contain the markup ${RANDOM} to inser random chars. Default empty."
 *   name="raModeNameGenerationPostfix"
 *   type="java.lang.String"
 *   value="${cmp.ra.namegenerationpostfix}"
 *   
 * @web.env-entry description="The endEntityProfile to be used when adding users in RA mode. Default EMPTY."
 *   name="endEntityProfile"
 *   type="java.lang.String"
 *   value="${cmp.ra.endentityprofile}"
 *   
 * @web.env-entry description="The certificateProfile to be used when adding users in RA mode. Default ENDUSER."
 *   name="certificateProfile"
 *   type="java.lang.String"
 *   value="${cmp.ra.certificateprofile}"
 *   
 * @web.env-entry description="The CA to be used when adding users in RA mode. Default AdminCA1."
 *   name="caName"
 *   type="java.lang.String"
 *   value="${cmp.ra.caname}"
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
 *  local="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *  
 * @web.ejb-local-ref
 *  name="ejb/CertificateStoreSessionLocal"
 *  type="Session"
 *  link="CertificateStoreSession"
 *  home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *  local="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *  
 */
public class CmpServlet extends HttpServlet {
	private static final Logger log = Logger.getLogger(CmpServlet.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
	
	/**
	 * Inits the CMP servlet
	 *
	 * @param config servlet configuration
	 *
	 * @throws ServletException on error during initialization
	 */
	public void init(ServletConfig config) throws ServletException {
		super.init(config);
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
		log.trace(">doPost()");
		/* 
		 POST
		 <binary CMP message>
		 */
		final ServletInputStream sin = request.getInputStream();
		final DERObject message;
		try {
			message = new LimitLengthASN1Reader(sin, request.getContentLength()).readObject();
		} catch ( Exception e ) {
			response.sendError(HttpServletResponse.SC_BAD_REQUEST, e.getMessage());
			log.error( intres.getLocalizedMessage("cmp.errornoasn1"), e );
			return;
		}
		service(message, request.getRemoteAddr(), response);
		log.trace("<doPost()");
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
		log.trace(">doGet()");
		
		log.info("Received un-allowed method GET in CMP servlet: query string=" + request.getQueryString());
		response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED, "You can only use POST!");
		
		log.trace("<doGet()");
	} // doGet

	private void service(DERObject message, String remoteAddr, HttpServletResponse response) throws IOException {
		try {
			// We must use an administrator with rights to create users
			final Admin administrator = new Admin(Admin.TYPE_RA_USER, remoteAddr);
			log.info( intres.getLocalizedMessage("cmp.receivedmsg", remoteAddr) );
			final CmpMessageDispatcher dispatcher = new CmpMessageDispatcher(administrator);
			final IResponseMessage resp = dispatcher.dispatch(message);
			if ( resp==null ) { // If resp is null, it means that the dispatcher failed to process the message.
				response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, intres.getLocalizedMessage("cmp.errornullresp"));
				return;
			}
			// Add no-cache headers as defined in draft-ietf-pkix-cmp-transport-protocols-05.txt
			ServletUtils.addCacheHeaders(response);
			// Send back CMP response
			RequestHelper.sendBinaryBytes(resp.getResponseMessage(), response, "application/pkixcmp", null);
			log.info( intres.getLocalizedMessage("cmp.sentresponsemsg", remoteAddr) );
		} catch (Exception e) {
			log.error("Error in CmpServlet:", e);
			response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, e.getMessage());
		}
	}

}
