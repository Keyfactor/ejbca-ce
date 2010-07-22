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
package org.ejbca.core.model.util;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbLocalHelper {

    private ISignSessionLocal signsession = null;
    public ISignSessionLocal getSignSession() throws CreateException {
    	if(signsession == null){	
    			ISignSessionLocalHome signhome = (ISignSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ISignSessionLocalHome.COMP_NAME);
    			signsession = signhome.create();
    	}
    	return signsession;
    }
    
    private ICAAdminSessionLocal casession = null;
    public ICAAdminSessionLocal getCAAdminSession() throws CreateException {
    	if(casession == null){	
    			ICAAdminSessionLocalHome cahome = (ICAAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
    			casession = cahome.create();
    	}
    	return casession;
    }

	private IAuthenticationSessionLocal authsession = null;
    public IAuthenticationSessionLocal getAuthenticationSession() throws CreateException {
    	if(authsession == null){	
    			IAuthenticationSessionLocalHome cahome = (IAuthenticationSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IAuthenticationSessionLocalHome.COMP_NAME);
    			authsession = cahome.create();
    	}
    	return authsession;
    }

	private IAuthorizationSessionLocal authorizationSession = null;
    public IAuthorizationSessionLocal getAuthorizationSession() throws CreateException {
    	if(authorizationSession == null){	
    			IAuthorizationSessionLocalHome home = (IAuthorizationSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
    			authorizationSession = home.create();
    	}
    	return authorizationSession;
    }

    private IKeyRecoverySessionLocal keyrecoverysession = null;
    public IKeyRecoverySessionLocal getKeyRecoverySession() throws CreateException {
    	if(keyrecoverysession == null){	
    			IKeyRecoverySessionLocalHome home = (IKeyRecoverySessionLocalHome)ServiceLocator.getInstance().getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
    			keyrecoverysession = home.create();
    	}
    	return keyrecoverysession;
    }

	private ICertificateStoreSessionLocal certificatestoresession = null;
	public ICertificateStoreSessionLocal getCertStoreSession() throws CreateException {
		if(certificatestoresession == null){
			ICertificateStoreSessionLocalHome home = (ICertificateStoreSessionLocalHome)ServiceLocator.getInstance().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
			certificatestoresession = home.create();
		}
		return certificatestoresession;
	}
	
	private IUserAdminSessionLocal usersession = null;
	public IUserAdminSessionLocal getUserAdminSession() throws CreateException {
		if(usersession == null){
			IUserAdminSessionLocalHome home = (IUserAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
			usersession = home.create();
		}
		return usersession;
	}
	
	private IRaAdminSessionLocal rasession = null;
	public IRaAdminSessionLocal getRAAdminSession() throws CreateException {
		if(rasession == null){
			IRaAdminSessionLocalHome home = (IRaAdminSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
			rasession = home.create();
		}
		return rasession;
	}

	private IApprovalSessionLocal approvalsession = null;	
	public IApprovalSessionLocal getApprovalSession() throws CreateException {
		if(approvalsession == null){
			IApprovalSessionLocalHome home = (IApprovalSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IApprovalSessionLocalHome.COMP_NAME); 
			approvalsession = home.create();
		}
		return approvalsession;
	}

	private IHardTokenSessionLocal hardtokensession = null;
	public IHardTokenSessionLocal getHardTokenSession() throws CreateException {
		if(hardtokensession == null){
			IHardTokenSessionLocalHome home = (IHardTokenSessionLocalHome)ServiceLocator.getInstance().getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
			hardtokensession = home.create();
		}
		return hardtokensession;
	}

}