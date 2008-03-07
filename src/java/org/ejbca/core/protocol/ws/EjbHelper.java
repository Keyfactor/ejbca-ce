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
package org.ejbca.core.protocol.ws;

import java.rmi.RemoteException;

import javax.ejb.CreateException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.ISignSessionHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionRemote;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionHome;
import org.ejbca.core.ejb.keyrecovery.IKeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.ILogSessionHome;
import org.ejbca.core.ejb.log.ILogSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id: EjbHelper.java,v 1.1 2008-03-07 14:07:40 anatom Exp $
 */
public class EjbHelper {

	/**
	 * return the environment entries locator
	 * @return return the environment entries locator
	 */
	private ServiceLocator getLocator() {
		return ServiceLocator.getInstance();
	}

	private ICAAdminSessionRemote caadminsession = null;
	public ICAAdminSessionRemote getCAAdminSession() throws RemoteException, ServiceLocatorException, CreateException  { 		
		if(caadminsession == null){	  
			caadminsession = ((ICAAdminSessionHome) getLocator().getRemoteHome(ICAAdminSessionHome.JNDI_NAME,ICAAdminSessionHome.class)).create();
		}
		return caadminsession;
	}

	private IRaAdminSessionRemote raadminsession = null;
	public IRaAdminSessionRemote getRAAdminSession() throws RemoteException, ServiceLocatorException, CreateException  {
		if(raadminsession == null){	  
			raadminsession = ((IRaAdminSessionHome) getLocator().getRemoteHome(IRaAdminSessionHome.JNDI_NAME,IRaAdminSessionHome.class)).create();
		}
		return raadminsession;
	}

	private ICertificateStoreSessionRemote certstoresession = null;
	public ICertificateStoreSessionRemote getCertStoreSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(certstoresession == null){	  
			certstoresession = ((ICertificateStoreSessionHome) getLocator().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME,ICertificateStoreSessionHome.class)).create();
		}
		return certstoresession;
	}

	private ISignSessionRemote signsession = null;
	public ISignSessionRemote getSignSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(signsession == null){	  
			signsession = ((ISignSessionHome) getLocator().getRemoteHome(ISignSessionHome.JNDI_NAME,ISignSessionHome.class)).create();
		}
		return signsession;
	}

	private IUserAdminSessionRemote useradmsession = null;
	public IUserAdminSessionRemote getUserAdminSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(useradmsession == null){	  
			useradmsession = ((IUserAdminSessionHome) getLocator().getRemoteHome(IUserAdminSessionHome.JNDI_NAME,IUserAdminSessionHome.class)).create();
		}
		return useradmsession;
	}

	private IKeyRecoverySessionRemote recoverysession = null;
	public IKeyRecoverySessionRemote getKeyRecoverySession() throws RemoteException, ServiceLocatorException, CreateException {
		if(recoverysession == null){	  
			recoverysession = ((IKeyRecoverySessionHome) getLocator().getRemoteHome(IKeyRecoverySessionHome.JNDI_NAME,IKeyRecoverySessionHome.class)).create();
		}
		return recoverysession;
	}

	private IHardTokenSessionRemote tokensession = null;
	public IHardTokenSessionRemote getHardTokenSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(tokensession == null){	  
			tokensession = ((IHardTokenSessionHome) getLocator().getRemoteHome(IHardTokenSessionHome.JNDI_NAME,IHardTokenSessionHome.class)).create();
		}
		return tokensession;
	}

	private IAuthorizationSessionRemote authsession = null;
	public IAuthorizationSessionRemote getAuthorizationSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(authsession == null){	  
			authsession = ((IAuthorizationSessionHome) getLocator().getRemoteHome(IAuthorizationSessionHome.JNDI_NAME,IAuthorizationSessionHome.class)).create();
		}
		return authsession;
	}

	private IApprovalSessionRemote approvalsession = null;
	public IApprovalSessionRemote getApprovalSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(approvalsession == null){	  
			approvalsession = ((IApprovalSessionHome) getLocator().getRemoteHome(IApprovalSessionHome.JNDI_NAME,IApprovalSessionHome.class)).create();
		}
		return approvalsession;
	}

	private IUserDataSourceSessionRemote dssession = null;
	public IUserDataSourceSessionRemote getUserDataSourceSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(dssession == null){	  
			dssession = ((IUserDataSourceSessionHome) getLocator().getRemoteHome(IUserDataSourceSessionHome.JNDI_NAME,IUserDataSourceSessionHome.class)).create();
		}
		return dssession;
	}

	private ILogSessionRemote logsession = null;
	public ILogSessionRemote getLogSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(logsession == null){	  
			logsession = ((ILogSessionHome) getLocator().getRemoteHome(ILogSessionHome.JNDI_NAME,ILogSessionHome.class)).create();
		}
		return logsession;
	}

	private IPublisherSessionRemote publishersession = null;
	public IPublisherSessionRemote getPublisherSession() throws RemoteException, ServiceLocatorException, CreateException {
		if(publishersession == null){	  
			publishersession = ((IPublisherSessionHome) getLocator().getRemoteHome(IPublisherSessionHome.JNDI_NAME,IPublisherSessionHome.class)).create();
		}
		return publishersession;
	}

}