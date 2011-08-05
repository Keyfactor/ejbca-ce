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

import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.core.ejb.authorization.AdminEntitySessionRemote;
import org.cesecore.core.ejb.authorization.AdminGroupSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.auth.OldAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.log.LogConfigurationSessionRemote;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.ejb.services.ServiceDataSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
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
	
	public static AdminEntitySessionRemote getAdminEntitySession() {
	    return getEjb().getAdminEntitySession();
	}

	public static AdminGroupSessionRemote getAdminGroupSession() {
	    return getEjb().getAdminGroupSession();
	}
	
	public static CAAdminSessionRemote getCAAdminSession() {
		return getEjb().getCAAdminSession();
	}

	public static CaSessionRemote getCaSession() {
	    return getEjb().getCaSession();
	}
	
	public static CertificateProfileSessionRemote getCertificateProfileSession() {
	    return getEjb().getCertificateProfileSession();
	}
	
	public static CrlCreateSessionRemote getCrlStoreSession() {
	    return getEjb().getCrlStoreSession();
	}
	
	public static RaAdminSessionRemote getRAAdminSession() {
		return getEjb().getRAAdminSession();
	}

	public static CertificateStoreSessionRemote getCertificateStoreSession() {
		return getEjb().getCertStoreSession();
	}
	
	public static EndEntityProfileSessionRemote getEndEntityProfileSession() {
	    return getEjb().getEndEntityProfileSession();
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

	public static OldAuthenticationSessionRemote getAuthenticationSession() {
		return getEjb().getAuthenticationSession();
	}

	public static ApprovalSessionRemote getApprovalSession() {
		return getEjb().getApprovalSession();
	}

	public static UserDataSourceSessionRemote getUserDataSourceSession() {
		return getEjb().getUserDataSourceSession();
	}

	public static LogConfigurationSessionRemote getLogConfigurationSession() {
		return getEjb().getLogConfigurationSession();
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
    
	public static CrlSessionRemote getCrlSession() {
		return getEjb().getCrlStoreSession();
	}

	public static CertificateRequestSessionRemote getCertficateRequestSession() {
		return getEjb().getCertficateRequestSession();
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

	public static ApprovalExecutionSessionRemote getApprovalExecutionSession() {
		return getEjb().getApprovalExecutionSession();
	}

	public static ServiceDataSessionRemote getServiceDataSessionRemote() {
		return getEjb().getServiceDataSession();
	}
	
	public static GlobalConfigurationSessionRemote getGlobalConfigurationSession() {
		return getEjb().getGlobalConfigurationSession();
	}
}
