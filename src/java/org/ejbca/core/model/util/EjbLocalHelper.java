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
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocal;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionLocalHome;

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

    private IKeyRecoverySessionLocal keyrecoverysession = null;
    public IKeyRecoverySessionLocal getKeyRecoverySession() throws CreateException {
    	if(keyrecoverysession == null){	
    			IKeyRecoverySessionLocalHome home = (IKeyRecoverySessionLocalHome)ServiceLocator.getInstance().getLocalHome(IKeyRecoverySessionLocalHome.COMP_NAME);
    			keyrecoverysession = home.create();
    	}
    	return keyrecoverysession;
    }

}