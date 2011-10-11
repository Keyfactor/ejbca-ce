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

import org.cesecore.audit.log.SecurityEventsLoggerSessionRemote;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionRemote;
import org.ejbca.core.ejb.config.ConfigurationSessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionRemote;
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
	
	public static AccessControlSessionRemote getAccessControlSession() {
	    return getEjb().getAccessControlSession();
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
	
	public static CrlCreateSessionRemote getCrlCreateSession() {
	    return getEjb().getCrlCreateSession();
	}
	
	public static AdminPreferenceSessionRemote getRAAdminSession() {
		return getEjb().getRAAdminSession();
	}

	public static CertificateStoreSessionRemote getCertificateStoreSession() {
		return getEjb().getCertStoreSession();
	}

	public static RevocationSessionRemote getRevocationSession() {
		return getEjb().getRevocationSession();
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

	public static EndEntityAccessSessionRemote getEndEntityAccessSession() {
		return getEjb().getEndEntityAccessSession();
	}

	public static KeyRecoverySessionRemote getKeyRecoverySession() {
		return getEjb().getKeyRecoverySession();
	}

	public static HardTokenSessionRemote getHardTokenSession() {
		return getEjb().getHardTokenSession();
	}

	public static EndEntityAuthenticationSessionRemote getAuthenticationSession() {
		return getEjb().getEndEntityAuthenticationSession();
	}

	public static ApprovalSessionRemote getApprovalSession() {
		return getEjb().getApprovalSession();
	}

	public static UserDataSourceSessionRemote getUserDataSourceSession() {
		return getEjb().getUserDataSourceSession();
	}

    public static PublisherQueueSessionRemote getPublisherQueueSession() {
		return getEjb().getPublisherQueueSession();
    }
    
	public static CrlStoreSessionRemote getCrlStoreSession() {
		return getEjb().getCrlStoreSession();
	}

	public static CertificateRequestSessionRemote getCertficateRequestSession() {
		return getEjb().getCertficateRequestSession();
	}

	public static UpgradeSessionRemote getUpgradeSession() {
		return getEjb().getUpgradeSession();
	}
	
	public static RoleAccessSessionRemote getRoleAccessSession() {
	    return getEjb().getRoleAccessSession();
	}

	public static RoleManagementSessionRemote getRoleManagementSession() {
	    return getEjb().getRoleManagementSession();
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
	
	public static CertReqHistorySessionRemote getCertReqHistorySession() {
		return getEjb().getCertReqHistorySession();
	}

	public static SecurityEventsLoggerSessionRemote getSecurityEventsLoggerSession() {
		return getEjb().getSecurityEventsLoggerSession();
	}
}
