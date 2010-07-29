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

import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.AuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.crl.CreateCRLSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.ejb.log.ProtectedLogSessionRemote;
import org.ejbca.core.ejb.protect.TableProtectSessionRemoteejb3;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbRemoteHelper {

	/*
	 * Return the environment entries locator. ServiceLocator caches the home interfaces.
	 * @return return the environment entries locator
	 * /
	private ServiceLocator getLocator() {
		return ServiceLocator.getInstance();
	}*/

	private CAAdminSessionRemote caadminsession = null;
	public CAAdminSessionRemote getCAAdminSession() { 		
		if(caadminsession == null){	  
			caadminsession = JndiHelper.getRemoteSession(CAAdminSessionRemote.class);
		}
		return caadminsession;
	}

	private RaAdminSessionRemote raadminsession = null;
	public RaAdminSessionRemote getRAAdminSession() {
		if(raadminsession == null){
			raadminsession = JndiHelper.getRemoteSession(RaAdminSessionRemote.class);
		}
		return raadminsession;
	}

	private CertificateStoreSessionRemote certstoresession = null;
	public CertificateStoreSessionRemote getCertStoreSession() {
		if(certstoresession == null){
			certstoresession = JndiHelper.getRemoteSession(CertificateStoreSessionRemote.class);
		}
		return certstoresession;
	}

	private SignSessionRemote signsession = null;
	public SignSessionRemote getSignSession() {
		if(signsession == null){	  
			signsession = JndiHelper.getRemoteSession(SignSessionRemote.class);
		}
		return signsession;
	}

	private UserAdminSessionRemote useradmsession = null;
	public UserAdminSessionRemote getUserAdminSession() {
		if(useradmsession == null){	  
			useradmsession = JndiHelper.getRemoteSession(UserAdminSessionRemote.class);
		}
		return useradmsession;
	}

	private KeyRecoverySessionRemote recoverysession = null;
	public KeyRecoverySessionRemote getKeyRecoverySession() {
		if(recoverysession == null){	  
			recoverysession = JndiHelper.getRemoteSession(KeyRecoverySessionRemote.class);
		}
		return recoverysession;
	}

	private HardTokenSessionRemote tokensession = null;
	public HardTokenSessionRemote getHardTokenSession() {
		if(tokensession == null){	  
			tokensession = JndiHelper.getRemoteSession(HardTokenSessionRemote.class);
		}
		return tokensession;
	}

	private AuthorizationSessionRemote authsession = null;
	public AuthorizationSessionRemote getAuthorizationSession() {
		if(authsession == null){	  
			authsession = JndiHelper.getRemoteSession(AuthorizationSessionRemote.class);
		}
		return authsession;
	}

	private AuthenticationSessionRemote authentsession = null;
	public AuthenticationSessionRemote getAuthenticationSession() {
		if(authentsession == null){	  
			authentsession = JndiHelper.getRemoteSession(AuthenticationSessionRemote.class);
		}
		return authentsession;
	}

	private ApprovalSessionRemote approvalsession = null;
	public ApprovalSessionRemote getApprovalSession() {
		if(approvalsession == null){	  
			approvalsession = JndiHelper.getRemoteSession(ApprovalSessionRemote.class);
		}
		return approvalsession;
	}

	private UserDataSourceSessionRemote dssession = null;
	public UserDataSourceSessionRemote getUserDataSourceSession() {
		if(dssession == null){	  
			dssession = JndiHelper.getRemoteSession(UserDataSourceSessionRemote.class);
		}
		return dssession;
	}

	private LogSessionRemote logsession = null;
	public LogSessionRemote getLogSession() {
		if(logsession == null){	  
			logsession = JndiHelper.getRemoteSession(LogSessionRemote.class);
		}
		return logsession;
	}

    private PublisherQueueSessionRemote publisherQueueSession = null;
    public PublisherQueueSessionRemote getPublisherQueueSession() {
        if(publisherQueueSession == null){
            publisherQueueSession = JndiHelper.getRemoteSession(PublisherQueueSessionRemote.class);
        }
        return this.publisherQueueSession;
    }
    
    private PublisherSessionRemote publishersession = null;
    public PublisherSessionRemote getPublisherSession() {
        if(publishersession == null){     
            publishersession = JndiHelper.getRemoteSession(PublisherSessionRemote.class);
        }
        return publishersession;
    }
    
	private CreateCRLSessionRemote crlsession = null;
	public CreateCRLSessionRemote getCrlSession() {
		if(crlsession == null){	  
			crlsession = JndiHelper.getRemoteSession(CreateCRLSessionRemote.class);
		}
		return crlsession;
	}

	private CertificateRequestSessionRemote certreqsession = null;
	public CertificateRequestSessionRemote getCertficateRequestSession() {
		if(certreqsession == null){	  
			certreqsession = JndiHelper.getRemoteSession(CertificateRequestSessionRemote.class);
		}
		return certreqsession;
	}

	private TableProtectSessionRemoteejb3 tableProtectSession = null;
	public TableProtectSessionRemoteejb3 getTableProtectSession() {
		if(tableProtectSession == null){	  
			tableProtectSession = JndiHelper.getRemoteSession(TableProtectSessionRemoteejb3.class);
		}
		return tableProtectSession;
	}

	private UpgradeSessionRemote upgradeSession = null;
	public UpgradeSessionRemote getUpgradeSession() {
		if (upgradeSession == null) {
			upgradeSession = JndiHelper.getRemoteSession(UpgradeSessionRemote.class);
		}
		return upgradeSession;
	}

	private ConfigurationSessionRemote configurationSession = null;
	public ConfigurationSessionRemote getConfigurationSession() {
		if (configurationSession == null) {
			configurationSession = JndiHelper.getRemoteSession(ConfigurationSessionRemote.class);
		}
		return configurationSession;
	}

	private ProtectedLogSessionRemote protectedLogSession;
	public ProtectedLogSessionRemote getProtectedLogSession() {
		if (protectedLogSession == null) {
			protectedLogSession = JndiHelper.getRemoteSession(ProtectedLogSessionRemote.class);
		}
		return protectedLogSession;
	}
}
