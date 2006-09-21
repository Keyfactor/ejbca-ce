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

package org.ejbca.core.protocol.cmp;

import javax.ejb.CreateException;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.SignRequestException;
import org.ejbca.core.model.ca.SignRequestSignatureException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.IResponseMessage;

/**
 * Message handler for certificate request messages in the CRMF format
 * @author tomas
 * @version $Id: CrmfMessageHandler.java,v 1.2 2006-09-21 11:33:33 anatom Exp $
 */
public class CrmfMessageHandler implements ICmpMessageHandler {
	
	private static Logger log = Logger.getLogger(CrmfMessageHandler.class);
	
	/** Defines which component from the DN should be used as username in EJBCA. Can be DN, UID or nothing. Nothing means that the DN will be used to look up the user. */
	private String extractUsernameComponent = null;
	
	private Admin admin;
	private ISignSessionLocal signsession = null;
	private IUserAdminSessionLocal usersession = null;
	
	public CrmfMessageHandler(Admin admin) throws CreateException {
		this.admin = admin;
		// Get EJB local bean
		ISignSessionLocalHome signHome = (ISignSessionLocalHome) ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
		this.signsession = signHome.create();
		IUserAdminSessionLocalHome userHome = (IUserAdminSessionLocalHome) ServiceLocator.getInstance().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
		this.usersession = userHome.create();
	}
	public IResponseMessage handleMessage(BaseCmpMessage msg) {
		log.debug(">handleMessage");
		IResponseMessage resp = null;
		try {
			CrmfRequestMessage crmfreq = null;
			if (msg instanceof CrmfRequestMessage) {
				crmfreq = (CrmfRequestMessage) msg;
				// if extractUsernameComponent is null, we have to find the user from the DN
				if (StringUtils.isEmpty(extractUsernameComponent)) {
					String dn = crmfreq.getSubjectDN();
					log.debug("looking for user with dn: "+dn);
					UserDataVO data = usersession.findUserBySubjectDN(admin, dn);
					if (data != null) {
						log.debug("Found username: "+data.getUsername());
						crmfreq.setUsername(data.getUsername());
					} else {
						log.info("Did not find a username matching dn: "+dn);
					}
				}
			} else {
				log.error("ICmpMessage if not aCrmfRequestMessage!");
			}
			// This is a request message, so we want to enroll for a certificate
			// Get the certificate
			resp = signsession.createCertificate(admin, crmfreq, -1,
					Class.forName("org.ejbca.core.protocol.cmp.CmpResponseMessage"));
			if (resp == null) {
				log.error("Response from signSession is null!");
			}
		} catch (AuthorizationDeniedException e) {
			log.error("Exception during CMP processing: ", e);			
		} catch (NotFoundException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (AuthStatusException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (AuthLoginException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (IllegalKeyException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (CADoesntExistsException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (SignRequestException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (SignRequestSignatureException e) {
			log.error("Exception during CMP processing: ", e);
		} catch (ClassNotFoundException e) {
			log.error("Exception during CMP processing: ", e);
		}
		return resp;
	}
	
}
