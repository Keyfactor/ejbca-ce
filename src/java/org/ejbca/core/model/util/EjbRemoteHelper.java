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

import java.rmi.RemoteException;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.ServiceLocatorException;
import org.ejbca.core.ejb.approval.IApprovalSessionHome;
import org.ejbca.core.ejb.approval.IApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionHome;
import org.ejbca.core.ejb.ca.auth.IAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherQueueSessionRemote;
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
import org.ejbca.core.ejb.ra.ICertificateRequestSessionHome;
import org.ejbca.core.ejb.ra.ICertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionRemote;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbRemoteHelper {

	/**
	 * Return the environment entries locator. ServiceLocator caches the home interfaces.
	 * @return return the environment entries locator
	 */
	private ServiceLocator getLocator() {
		return ServiceLocator.getInstance();
	}

	private ICAAdminSessionRemote caadminsession = null;
	public ICAAdminSessionRemote getCAAdminSession() { 		
		if(caadminsession == null){	  
			try {
				caadminsession = ((ICAAdminSessionHome) getLocator().getRemoteHome(ICAAdminSessionHome.JNDI_NAME,ICAAdminSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return caadminsession;
	}

	private IRaAdminSessionRemote raadminsession = null;
	public IRaAdminSessionRemote getRAAdminSession() {
		if(raadminsession == null){
			try {
				raadminsession = ((IRaAdminSessionHome) getLocator().getRemoteHome(IRaAdminSessionHome.JNDI_NAME,IRaAdminSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return raadminsession;
	}

	private ICertificateStoreSessionRemote certstoresession = null;
	public ICertificateStoreSessionRemote getCertStoreSession() {
		if(certstoresession == null){
			try {
				certstoresession = ((ICertificateStoreSessionHome) getLocator().getRemoteHome(ICertificateStoreSessionHome.JNDI_NAME,ICertificateStoreSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return certstoresession;
	}

	private ISignSessionRemote signsession = null;
	public ISignSessionRemote getSignSession() {
		if(signsession == null){	  
			try {
				signsession = ((ISignSessionHome) getLocator().getRemoteHome(ISignSessionHome.JNDI_NAME,ISignSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return signsession;
	}

	private IUserAdminSessionRemote useradmsession = null;
	public IUserAdminSessionRemote getUserAdminSession() {
		if(useradmsession == null){	  
			try {
				useradmsession = ((IUserAdminSessionHome) getLocator().getRemoteHome(IUserAdminSessionHome.JNDI_NAME,IUserAdminSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return useradmsession;
	}

	private IKeyRecoverySessionRemote recoverysession = null;
	public IKeyRecoverySessionRemote getKeyRecoverySession() {
		if(recoverysession == null){	  
			try {
				recoverysession = ((IKeyRecoverySessionHome) getLocator().getRemoteHome(IKeyRecoverySessionHome.JNDI_NAME,IKeyRecoverySessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return recoverysession;
	}

	private IHardTokenSessionRemote tokensession = null;
	public IHardTokenSessionRemote getHardTokenSession() {
		if(tokensession == null){	  
			try {
				tokensession = ((IHardTokenSessionHome) getLocator().getRemoteHome(IHardTokenSessionHome.JNDI_NAME,IHardTokenSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return tokensession;
	}

	private IAuthorizationSessionRemote authsession = null;
	public IAuthorizationSessionRemote getAuthorizationSession() {
		if(authsession == null){	  
			try {
				authsession = ((IAuthorizationSessionHome) getLocator().getRemoteHome(IAuthorizationSessionHome.JNDI_NAME,IAuthorizationSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return authsession;
	}

	private IAuthenticationSessionRemote authentsession = null;
	public IAuthenticationSessionRemote getAuthenticationSession() {
		if(authentsession == null){	  
			try {
				authentsession = ((IAuthenticationSessionHome) getLocator().getRemoteHome(IAuthenticationSessionHome.JNDI_NAME,IAuthenticationSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return authentsession;
	}

	private IApprovalSessionRemote approvalsession = null;
	public IApprovalSessionRemote getApprovalSession() {
		if(approvalsession == null){	  
			try {
				approvalsession = ((IApprovalSessionHome) getLocator().getRemoteHome(IApprovalSessionHome.JNDI_NAME,IApprovalSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return approvalsession;
	}

	private IUserDataSourceSessionRemote dssession = null;
	public IUserDataSourceSessionRemote getUserDataSourceSession() {
		if(dssession == null){	  
			try {
				dssession = ((IUserDataSourceSessionHome) getLocator().getRemoteHome(IUserDataSourceSessionHome.JNDI_NAME,IUserDataSourceSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return dssession;
	}

	private ILogSessionRemote logsession = null;
	public ILogSessionRemote getLogSession() {
		if(logsession == null){	  
			try {
				logsession = ((ILogSessionHome) getLocator().getRemoteHome(ILogSessionHome.JNDI_NAME,ILogSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return logsession;
	}

    private IPublisherQueueSessionRemote publisherQueueSession;
    public IPublisherQueueSessionRemote getPublisherQueueSession() {
        if(this.publisherQueueSession != null){
            return this.publisherQueueSession;
        }
        try {
            this.publisherQueueSession = ((IPublisherQueueSessionHome) getLocator().getRemoteHome(IPublisherQueueSessionHome.JNDI_NAME,IPublisherQueueSessionHome.class)).create();
        } catch (RemoteException e) {
            throw new EJBException(e);
        } catch (ServiceLocatorException e) {
            throw new EJBException(e);
        } catch (CreateException e) {
            throw new EJBException(e);
        }
        return this.publisherQueueSession;
    }
    
    private IPublisherSessionRemote publishersession = null;
    public IPublisherSessionRemote getPublisherSession() {
        if(publishersession == null){     
            try {
                publishersession = ((IPublisherSessionHome) getLocator().getRemoteHome(IPublisherSessionHome.JNDI_NAME,IPublisherSessionHome.class)).create();
            } catch (RemoteException e) {
                throw new EJBException(e);
            } catch (ServiceLocatorException e) {
                throw new EJBException(e);
            } catch (CreateException e) {
                throw new EJBException(e);
            }
        }
        return publishersession;
    }
    
	private ICreateCRLSessionRemote crlsession = null;
	public ICreateCRLSessionRemote getCrlSession() {
		if(crlsession == null){	  
			try {
				crlsession = ((ICreateCRLSessionHome) getLocator().getRemoteHome(ICreateCRLSessionHome.JNDI_NAME,ICreateCRLSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return crlsession;
	}

	private ICertificateRequestSessionRemote certreqsession = null;
	public ICertificateRequestSessionRemote getCertficateRequestSession() {
		if(certreqsession == null){	  
			try {
				certreqsession = ((ICertificateRequestSessionHome) getLocator().getRemoteHome(ICertificateRequestSessionHome.JNDI_NAME,ICertificateRequestSessionHome.class)).create();
			} catch (RemoteException e) {
				throw new EJBException(e);
			} catch (ServiceLocatorException e) {
				throw new EJBException(e);
			} catch (CreateException e) {
				throw new EJBException(e);
			}
		}
		return certreqsession;
	}
}
