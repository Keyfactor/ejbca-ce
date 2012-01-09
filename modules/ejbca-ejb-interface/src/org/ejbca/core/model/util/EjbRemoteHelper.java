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

import org.cesecore.audit.log.SecurityEventsLoggerSessionRemote;
import org.cesecore.authorization.control.AccessControlSessionRemote;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.jndi.JndiHelper;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionRemote;
import org.ejbca.core.ejb.approval.ApprovalSessionRemote;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderRemote;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionRemote;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.CertificateRequestSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.ejb.services.ServiceDataSessionRemote;
import org.ejbca.core.ejb.services.ServiceSessionRemote;
import org.ejbca.core.ejb.upgrade.UpgradeSessionRemote;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionRemote;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbRemoteHelper {

    private ApprovalSessionRemote approvalSession = null;
    private ApprovalExecutionSessionRemote approvalExecutionSession = null;
    private AccessControlSessionRemote accessControlSession = null;
    private CAAdminSessionRemote caAdminSession = null;
    private CaSessionRemote caSession = null;
    private CertificateProfileSessionRemote certificateProfileSession = null;
    private CertificateRequestSessionRemote certificateRequestSession = null;
    private CertificateStoreSessionRemote certificateStoreSession = null;
    private CertReqHistorySessionRemote certReqHistorySession = null;
    private CmpMessageDispatcherSessionRemote cmpMessageDispatcherSession = null;
    private ComplexAccessControlSessionRemote complexAccessControlSessionRemote = null;
    private CrlStoreSessionRemote crlSession = null;
    private CrlCreateSessionRemote crlStoreSession = null;
    private EndEntityAccessSessionRemote endEntityAccessSession = null;
    private EndEntityAuthenticationSessionRemote endEntityAuthenticationSession = null;
    private EndEntityProfileSessionRemote endEntityProfileSession = null;
    private GlobalConfigurationSessionRemote globalConfigurationSession;
    private HardTokenSessionRemote hardTokenSession = null;
    private KeyRecoverySessionRemote keyRecoverySession = null;
    private PublisherQueueSessionRemote publisherQueueSession = null;
    private PublisherSessionRemote publisherSession = null;
    private AdminPreferenceSessionRemote raAdminSession = null;  
    private RevocationSessionRemote revocationSession = null;
    private RoleAccessSessionRemote roleAccessSession = null;
    private RoleManagementSessionRemote roleManagementSession = null;
    private SecurityEventsLoggerSessionRemote securityEventsLoggerSession = null;
    private ServiceDataSessionRemote serviceDataSession = null;
    private ServiceSessionRemote serviceSession = null;
    private SignSessionRemote signSession = null;
    private UpgradeSessionRemote upgradeSession = null;
    private UserAdminSessionRemote userAdminSession = null;
    private UserDataSourceSessionRemote userDataSourceSession = null;
   
    private CliAuthenticationProviderRemote cliAuthenticationProvider = null;
    
    public RoleAccessSessionRemote getRoleAccessSession() {
        if (roleAccessSession == null) {
            roleAccessSession = JndiHelper.getRemoteSession(RoleAccessSessionRemote.class);
        }
        return roleAccessSession;
    }

    public CaSessionRemote getCaSession() {
        if (caSession == null) {
            caSession = JndiHelper.getRemoteSession(CaSessionRemote.class);
        }
        return caSession;
    }

    public CAAdminSessionRemote getCAAdminSession() {
        if (caAdminSession == null) {
            caAdminSession = JndiHelper.getRemoteSession(CAAdminSessionRemote.class);
        }
        return caAdminSession;
    }

    public CertificateProfileSessionRemote getCertificateProfileSession() {
        if (certificateProfileSession == null) {
            certificateProfileSession = JndiHelper.getRemoteSession(CertificateProfileSessionRemote.class);
        }
        return certificateProfileSession;
    }

    public CmpMessageDispatcherSessionRemote getCmpMessageDispatcherSession() {
        if (cmpMessageDispatcherSession == null) {
            cmpMessageDispatcherSession = JndiHelper.getRemoteSession(CmpMessageDispatcherSessionRemote.class);
        }
        return cmpMessageDispatcherSession;
    }

    public ComplexAccessControlSessionRemote getComplexAccessControlSession() {
        if (complexAccessControlSessionRemote == null) {
            complexAccessControlSessionRemote = JndiHelper.getRemoteSession(ComplexAccessControlSessionRemote.class);
        }
        return complexAccessControlSessionRemote;
    }

    public CrlCreateSessionRemote getCrlCreateSession() {
        if (crlStoreSession == null) {
            crlStoreSession = JndiHelper.getRemoteSession(CrlCreateSessionRemote.class);
        }
        return crlStoreSession;
    }

    public EndEntityProfileSessionRemote getEndEntityProfileSession() {
        if (endEntityProfileSession == null) {
            endEntityProfileSession = JndiHelper.getRemoteSession(EndEntityProfileSessionRemote.class);
        }
        return endEntityProfileSession;
    }

    public AdminPreferenceSessionRemote getRAAdminSession() {
        if (raAdminSession == null) {
            raAdminSession = JndiHelper.getRemoteSession(AdminPreferenceSessionRemote.class);
        }
        return raAdminSession;
    }

    public GlobalConfigurationSessionRemote getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) {
            globalConfigurationSession = JndiHelper.getRemoteSession(GlobalConfigurationSessionRemote.class);
        }
        return globalConfigurationSession;
    }

    public CertificateStoreSessionRemote getCertStoreSession() {
        if (certificateStoreSession == null) {
            certificateStoreSession = JndiHelper.getRemoteSession(CertificateStoreSessionRemote.class);
        }
        return certificateStoreSession;
    }

    public SignSessionRemote getSignSession() {
        if (signSession == null) {
            signSession = JndiHelper.getRemoteSession(SignSessionRemote.class);
        }
        return signSession;
    }

    public UserAdminSessionRemote getUserAdminSession() {
        if (userAdminSession == null) {
            userAdminSession = JndiHelper.getRemoteSession(UserAdminSessionRemote.class);
        }
        return userAdminSession;
    }

    public KeyRecoverySessionRemote getKeyRecoverySession() {
        if (keyRecoverySession == null) {
            keyRecoverySession = JndiHelper.getRemoteSession(KeyRecoverySessionRemote.class);
        }
        return keyRecoverySession;
    }

    public HardTokenSessionRemote getHardTokenSession() {
        if (hardTokenSession == null) {
            hardTokenSession = JndiHelper.getRemoteSession(HardTokenSessionRemote.class);
        }
        return hardTokenSession;
    }

    public EndEntityAuthenticationSessionRemote getEndEntityAuthenticationSession() {
        if (endEntityAuthenticationSession == null) {
            endEntityAuthenticationSession = JndiHelper.getRemoteSession(EndEntityAuthenticationSessionRemote.class);
        }
        return endEntityAuthenticationSession;
    }

    public ApprovalSessionRemote getApprovalSession() {
        if (approvalSession == null) {
            approvalSession = JndiHelper.getRemoteSession(ApprovalSessionRemote.class);
        }
        return approvalSession;
    }

    public UserDataSourceSessionRemote getUserDataSourceSession() {
        if (userDataSourceSession == null) {
            userDataSourceSession = JndiHelper.getRemoteSession(UserDataSourceSessionRemote.class);
        }
        return userDataSourceSession;
    }

    public PublisherQueueSessionRemote getPublisherQueueSession() {
        if (publisherQueueSession == null) {
            publisherQueueSession = JndiHelper.getRemoteSession(PublisherQueueSessionRemote.class);
        }
        return publisherQueueSession;
    }

    public PublisherSessionRemote getPublisherSession() {
        if (publisherSession == null) {
            publisherSession = JndiHelper.getRemoteSession(PublisherSessionRemote.class);
        }
        return publisherSession;
    }

    public CrlStoreSessionRemote getCrlStoreSession() {
        if (crlSession == null) {
            crlSession = JndiHelper.getRemoteSession(CrlStoreSessionRemote.class);
        }
        return crlSession;
    }

    public CertificateRequestSessionRemote getCertficateRequestSession() {
        if (certificateRequestSession == null) {
            certificateRequestSession = JndiHelper.getRemoteSession(CertificateRequestSessionRemote.class);
        }
        return certificateRequestSession;
    }

    public UpgradeSessionRemote getUpgradeSession() {
        if (upgradeSession == null) {
            upgradeSession = JndiHelper.getRemoteSession(UpgradeSessionRemote.class);
        }
        return upgradeSession;
    }

	public SecurityEventsLoggerSessionRemote getSecurityEventsLoggerSession() {
        if (securityEventsLoggerSession == null) {
            securityEventsLoggerSession = JndiHelper.getRemoteSession(SecurityEventsLoggerSessionRemote.class);
        }
        return securityEventsLoggerSession;
	}

    public ServiceDataSessionRemote getServiceDataSession() {
        if (serviceDataSession == null) {
            serviceDataSession = JndiHelper.getRemoteSession(ServiceDataSessionRemote.class);
        }
        return serviceDataSession;
    }

    public ServiceSessionRemote getServiceSession() {
        if (serviceSession == null) {
            serviceSession = JndiHelper.getRemoteSession(ServiceSessionRemote.class);
        }
        return serviceSession;
    }

    public ApprovalExecutionSessionRemote getApprovalExecutionSession() {
        if (approvalExecutionSession == null) {
            approvalExecutionSession = JndiHelper.getRemoteSession(ApprovalExecutionSessionRemote.class);
        }
        return approvalExecutionSession;
    }

    public CertReqHistorySessionRemote getCertReqHistorySession() {
        if (certReqHistorySession == null) {
            certReqHistorySession = JndiHelper.getRemoteSession(CertReqHistorySessionRemote.class);
        }
        return certReqHistorySession;
    }

    public AccessControlSessionRemote getAccessControlSession() {
        if (accessControlSession == null) {
            accessControlSession = JndiHelper.getRemoteSession(AccessControlSessionRemote.class);
        }
        return accessControlSession;
    }

    public RevocationSessionRemote getRevocationSession() {
        if (revocationSession == null) {
            revocationSession = JndiHelper.getRemoteSession(RevocationSessionRemote.class);
        }
        return revocationSession;
    }
    
    public RoleManagementSessionRemote getRoleManagementSession() {
        if(roleManagementSession == null) {
            roleManagementSession = JndiHelper.getRemoteSession(RoleManagementSessionRemote.class);
        }
        return roleManagementSession;
    }
    
    public EndEntityAccessSessionRemote getEndEntityAccessSession() {
        if(endEntityAccessSession == null) {
            endEntityAccessSession = JndiHelper.getRemoteSession(EndEntityAccessSessionRemote.class);
        }
        return endEntityAccessSession;
    }
    
    public CliAuthenticationProviderRemote getCliAuthenticationProvider() {
        if(cliAuthenticationProvider == null) {
            cliAuthenticationProvider = JndiHelper.getRemoteSession(CliAuthenticationProviderRemote.class);
        }
        return cliAuthenticationProvider;
    }
}
