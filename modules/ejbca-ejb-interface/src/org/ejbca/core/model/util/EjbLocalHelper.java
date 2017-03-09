/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.util.concurrent.locks.ReentrantLock;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.authorization.rules.AccessRuleManagementSessionLocal;
import org.cesecore.authorization.user.AccessUserAspectManagerSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.EjbcaAuditorSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.statedump.ejb.StatedumpSession;
import org.ejbca.statedump.ejb.StatedumpSessionLocal;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbLocalHelper implements EjbBridgeSessionLocal {
	
    private static final Logger log = Logger.getLogger(EjbLocalHelper.class);
	private static Context initialContext = null;
	private static ReentrantLock initialContextLock = new ReentrantLock(true);
	// Static is more performant, but a failed JEE5 lookup from one module would block all other JEE5 lookups
	private /*static*/ boolean useEjb31GlobalJndiName = false;
	
	public static final String DEFAULT_MODULE = "ejbca-ejb";

	private static Context getInitialContext() throws NamingException {
		try {
			initialContextLock.lock();
			if (initialContext == null) {
				initialContext = new InitialContext();
			}
			return initialContext;
		} finally {
			initialContextLock.unlock();
		}
	}

	/**
	 * Requires a "ejb-local-ref" definition in web.xml and ejb-jar.xml from all accessing components
	 * or an application server that support global JNDI names (introduced in EJB 3.1).
	 * @return a reference to the bridge SSB
	 * 
	 * @throws LocalLookupException if local lookup couldn't be made.
	 */
	private EjbBridgeSessionLocal getEjbLocal() {
		EjbBridgeSessionLocal ret = null;
		try {
			if (!useEjb31GlobalJndiName) {
				ret = (EjbBridgeSessionLocal) getInitialContext().lookup("java:comp/env/EjbBridgeSession");
			}
		} catch (NamingException e) {
			// Let's try to use the EJB 3.1 syntax for a lookup. For example, JBoss 6.0.0.FINAL supports this from our CMP TCP threads, but ignores the ejb-ref from web.xml..
			// java:global[/<app-name>]/<module-name>/<bean-name>[!<fully-qualified-interface-name>]
			useEjb31GlobalJndiName = true;	// So let's not try what we now know is a failing method ever again..
			if (log.isDebugEnabled()) {
	            log.debug("Failed JEE5 version of EjbBridgeSessionLocal JNDI lookup. All future lookups will JEE6 version lookups.");
			}
		}
		try {
			if (useEjb31GlobalJndiName) {
				ret = (EjbBridgeSessionLocal) getInitialContext().lookup("java:global/ejbca/"+DEFAULT_MODULE+"/EjbBridgeSessionBean!org.ejbca.core.ejb.EjbBridgeSessionLocal");
			}
		} catch (NamingException e) {
			throw new LocalLookupException("Cannot lookup EjbBridgeSessionLocal.", e);
		}
		return ret;
	}

	@Override public AccessRuleManagementSessionLocal getAccessRuleManagementSession() { return getEjbLocal().getAccessRuleManagementSession(); }
	@Deprecated @Override public AccessUserAspectManagerSessionLocal getAccessUserAspectSession() { return getEjbLocal().getAccessUserAspectSession(); }
	@Override public ApprovalExecutionSessionLocal getApprovalExecutionSession() { return getEjbLocal().getApprovalExecutionSession(); }
	@Override public ApprovalSessionLocal getApprovalSession() { return getEjbLocal().getApprovalSession(); }
	@Override public ApprovalProfileSessionLocal getApprovalProfileSession() { return getEjbLocal().getApprovalProfileSession(); }
	@Deprecated @Override public AccessControlSessionLocal getAccessControlSession()  { return getEjbLocal().getAccessControlSession(); }
    @Override public AuthorizationSessionLocal getAuthorizationSession() { return getEjbLocal().getAuthorizationSession(); }
    @Override public AuthorizationSystemSessionLocal getAuthorizationSystemSession() { return getEjbLocal().getAuthorizationSystemSession(); }
	@Override public CAAdminSessionLocal getCaAdminSession() { return getEjbLocal().getCaAdminSession(); }
	@Override public CaSessionLocal getCaSession() { return getEjbLocal().getCaSession(); }
	@Override public CertificateCreateSessionLocal getCertificateCreateSession() { return getEjbLocal().getCertificateCreateSession(); }
	@Override public CertificateProfileSessionLocal getCertificateProfileSession() { return getEjbLocal().getCertificateProfileSession(); }
	@Override public CertificateStoreSessionLocal getCertificateStoreSession() { return getEjbLocal().getCertificateStoreSession(); }
	@Override public CertReqHistorySessionLocal getCertReqHistorySession() { return getEjbLocal().getCertReqHistorySession(); }
	@Override public ComplexAccessControlSessionLocal getComplexAccessControlSession() { return getEjbLocal().getComplexAccessControlSession(); }
	@Override public RevocationSessionLocal getRevocationSession() { return getEjbLocal().getRevocationSession(); }
	@Override public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return getEjbLocal().getCmpMessageDispatcherSession(); }
	@Override public CrlCreateSessionLocal getCrlCreateSession() { return getEjbLocal().getCrlCreateSession(); }
	@Override public CrlStoreSessionLocal getCrlStoreSession() { return getEjbLocal().getCrlStoreSession(); }
    @Override public EjbcaAuditorSessionLocal getEjbcaAuditorSession() { return getEjbLocal().getEjbcaAuditorSession(); }
	@Override public EndEntityAccessSessionLocal getEndEntityAccessSession() { return getEjbLocal().getEndEntityAccessSession(); }
	@Override public EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession() { return getEjbLocal().getEndEntityAuthenticationSession(); }
	@Override public EndEntityProfileSessionLocal getEndEntityProfileSession() { return getEjbLocal().getEndEntityProfileSession(); }
	@Override public GlobalConfigurationSessionLocal getGlobalConfigurationSession() { return getEjbLocal().getGlobalConfigurationSession(); }
	@Override public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() { return getEjbLocal().getHardTokenBatchJobSession(); }
	@Override public HardTokenSessionLocal getHardTokenSession() { return getEjbLocal().getHardTokenSession(); }
	@Override public KeyRecoverySessionLocal getKeyRecoverySession() { return getEjbLocal().getKeyRecoverySession(); }
	@Override public EndEntityManagementSessionLocal getEndEntityManagementSession() { return getEjbLocal().getEndEntityManagementSession(); }
	@Override public AdminPreferenceSessionLocal getRaAdminSession() { return getEjbLocal().getRaAdminSession(); }
	@Override public PublisherQueueSessionLocal getPublisherQueueSession() { return getEjbLocal().getPublisherQueueSession(); }
	@Override public PublisherSessionLocal getPublisherSession() { return getEjbLocal().getPublisherSession(); }
    @Override public RaMasterApiProxyBeanLocal getRaMasterApiProxyBean() { return getEjbLocal().getRaMasterApiProxyBean(); }
    @Deprecated @Override public RoleAccessSessionLocal getRoleAccessSession() { return getEjbLocal().getRoleAccessSession(); }
    @Deprecated @Override public RoleManagementSessionLocal getRoleManagementSession() { return getEjbLocal().getRoleManagementSession(); }
    @Override public RoleMemberSessionLocal getRoleMemberSession() { return getEjbLocal().getRoleMemberSession(); }
    @Override public RoleSessionLocal getRoleSession() {return getEjbLocal().getRoleSession(); }
    @Override public RoleDataSessionLocal getRoleDataSession() {return getEjbLocal().getRoleDataSession(); }
	@Override public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() { return getEjbLocal().getSecurityEventsAuditorSession(); }
	@Override public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() { return getEjbLocal().getSecurityEventsLoggerSession(); }
	@Override public ServiceSessionLocal getServiceSession() { return getEjbLocal().getServiceSession(); }
	@Override public SignSessionLocal getSignSession() { return getEjbLocal().getSignSession(); }
	@Override public UpgradeSessionLocal getUpgradeSession() {return getEjbLocal().getUpgradeSession(); }
	@Override public UserDataSourceSessionLocal getUserDataSourceSession() { return getEjbLocal().getUserDataSourceSession(); }
	@Override public WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession() { return getEjbLocal().getWebAuthenticationProviderSession(); }
	@Override public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() { return getEjbLocal().getCryptoTokenManagementSession(); }
    @Override public InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() { return getEjbLocal().getInternalKeyBindingMgmtSession(); }
    @Override public PublishingCrlSessionLocal getPublishingCrlSession() { return getEjbLocal().getPublishingCrlSession(); }
    @Override public ImportCrlSessionLocal getImportCrlSession() { return getEjbLocal().getImportCrlSession(); }
    

    /** 
     * Dynamically loads the StatedumpSession with JNDI. It's usually not available in the EJBCA source tree,
     * and in this case this is properly handled  by returning null.
     * 
     * @return A statedump session object, or null if not available.
     */
    public StatedumpSessionLocal getStatedumpSession() {
        try {
            if (!useEjb31GlobalJndiName) {
                return (StatedumpSessionLocal) getInitialContext().lookup("java:comp/env/StatedumpSession");
            }
        } catch (NamingException e) {
            // NOPMD ignore and continue
        }
        
        // Try using EJB 3.1 name
        try {
            return (StatedumpSessionLocal) getInitialContext().lookup("java:global/ejbca/"+StatedumpSession.STATEDUMP_MODULE+"/StatedumpSessionBean!org.ejbca.statedump.ejb.StatedumpSessionLocal");
        } catch (NamingException e) {
            return null; // this is the common case, since statedump is an internal tool and is not included with EJBCA
        }
    }
}
