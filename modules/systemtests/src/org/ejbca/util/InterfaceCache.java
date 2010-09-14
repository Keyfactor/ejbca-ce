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

package org.ejbca.util;

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
import org.ejbca.core.ejb.protect.TableProtectSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.ejb.upgrade.ConfigurationSessionRemote;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.core.model.util.EjbRemoteHelper;

/**
 * This class will cache remote EJB stubs, so we don't have to do the expensive lookup for each JUnit test method.
 * 
 * @version $Id$
 */
public class InterfaceCache {

	private static EjbRemoteHelper ejb = null;
	
	private static EjbRemoteHelper getEjb() {
		if (ejb == null) {
			ejb = new EjbRemoteHelper();
		}
		return ejb;
	}

	public static CAAdminSessionRemote getCAAdminSession() {
		return getEjb().getCAAdminSession();
	}

	public static RaAdminSessionRemote getRAAdminSession() {
		return getEjb().getRAAdminSession();
	}

	public static CertificateStoreSessionRemote getCertificateStoreSession() {
		return getEjb().getCertStoreSession();
	}

	public static SignSessionRemote getSignSession() {
		return getEjb().getSignSession();
	}

	public static UserAdminSessionRemote getUserAdminSession() {
		return getEjb().getUserAdminSession();
	}

	public static KeyRecoverySessionRemote getKeyRecoverySession() {
		return getEjb().getKeyRecoverySession();
	}

	public static HardTokenSessionRemote getHardTokenSession() {
		return getEjb().getHardTokenSession();
	}

	public static AuthorizationSessionRemote getAuthorizationSession() {
		return getEjb().getAuthorizationSession();
	}

	public static AuthenticationSessionRemote getAuthenticationSession() {
		return getEjb().getAuthenticationSession();
	}

	public static ApprovalSessionRemote getApprovalSession() {
		return getEjb().getApprovalSession();
	}

	public static UserDataSourceSessionRemote getUserDataSourceSession() {
		return getEjb().getUserDataSourceSession();
	}

	public static LogSessionRemote getLogSession() {
		return getEjb().getLogSession();
	}

    public static PublisherQueueSessionRemote getPublisherQueueSession() {
		return getEjb().getPublisherQueueSession();
    }
    
    public static PublisherSessionRemote getPublisherSession() {
		return getEjb().getPublisherSession();
    }
    
	public static CreateCRLSessionRemote getCrlSession() {
		return getEjb().getCrlSession();
	}

	public static CertificateRequestSessionRemote getCertficateRequestSession() {
		return getEjb().getCertficateRequestSession();
	}

	public static TableProtectSessionRemote getTableProtectSession() {
		return getEjb().getTableProtectSession();
	}

	public static UpgradeSessionRemote getUpgradeSession() {
		return getEjb().getUpgradeSession();
	}

	public static ConfigurationSessionRemote getConfigurationSession() {
		return getEjb().getConfigurationSession();
	}

	public static ServiceSessionRemote getServiceSession() {
		return getEjb().getServiceSession();
	}
}
