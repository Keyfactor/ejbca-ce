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

import java.util.concurrent.locks.ReentrantLock;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;

import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authentication.AuthenticationSessionLocal;
import org.cesecore.authorization.control.AccessControlSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.core.ejb.authorization.AdminEntitySessionLocal;
import org.cesecore.core.ejb.authorization.AdminGroupSessionLocal;
import org.cesecore.mock.authentication.SimpleAuthenticationProviderLocal;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSessionLocal;
import org.ejbca.core.ejb.ca.auth.OldAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSessionLocal;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.log.LogConfigurationSessionLocal;
import org.ejbca.core.ejb.log.LogSessionLocal;
import org.ejbca.core.ejb.log.OldLogSessionLocal;
import org.ejbca.core.ejb.ra.UserAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbLocalHelper implements EjbBridgeSessionLocal {
	
	private static Context initialContext = null;
	private static ReentrantLock initialContextLock = new ReentrantLock(true);
	private static boolean useEjb31GlobalJndiName = false;
	
	private Context getInitialContext() throws NamingException {
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
		}
		try {
			if (useEjb31GlobalJndiName) {
				ret = (EjbBridgeSessionLocal) getInitialContext().lookup("java:global/ejbca/ejbca-ejb/EjbBridgeSessionBean!org.ejbca.core.ejb.EjbBridgeSessionLocal");
			}
		} catch (NamingException e) {
			throw new RuntimeException("Cannot lookup EjbBridgeSessionLocal.", e);
		}
		return ret;
	}

	@Override public AdminEntitySessionLocal getAdminEntitySession() { return getEjbLocal().getAdminEntitySession(); }
	@Override public AdminGroupSessionLocal getAdminGroupSession() { return getEjbLocal().getAdminGroupSession(); }
	@Override public ApprovalExecutionSessionLocal getApprovalExecutionSession() { return getEjbLocal().getApprovalExecutionSession(); }
	@Override public ApprovalSessionLocal getApprovalSession() { return getEjbLocal().getApprovalSession(); }
	@Override public AuthenticationSessionLocal getAuthenticationSession() { return getEjbLocal().getAuthenticationSession(); }
	@Deprecated @Override public OldAuthenticationSessionLocal getOldAuthenticationSession() { return getEjbLocal().getOldAuthenticationSession(); }
	@Override public AuthorizationSessionLocal getAuthorizationSession()  { return getEjbLocal().getAuthorizationSession(); }
	@Override public AccessControlSessionLocal getAccessControlSession()  { return getEjbLocal().getAccessControlSession(); }
	@Override public CAAdminSessionLocal getCaAdminSession() { return getEjbLocal().getCaAdminSession(); }
	@Override public CaSessionLocal getCaSession() { return getEjbLocal().getCaSession(); }
	@Override public CertificateProfileSessionLocal getCertificateProfileSession() { return getEjbLocal().getCertificateProfileSession(); }
	@Override public CertificateStoreSessionLocal getCertificateStoreSession() { return getEjbLocal().getCertificateStoreSession(); }
	@Override public CertReqHistorySessionLocal getCertReqHistorySession() { return getEjbLocal().getCertReqHistorySession(); }
	@Override public RevocationSessionLocal getRevocationSession() { return getEjbLocal().getRevocationSession(); }
	@Override public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return getEjbLocal().getCmpMessageDispatcherSession(); }
	@Override public CrlCreateSessionLocal getCrlCreateSession() { return getEjbLocal().getCrlCreateSession(); }
	@Override public CrlStoreSessionLocal getCrlStoreSession() { return getEjbLocal().getCrlStoreSession(); }
	@Override public EndEntityProfileSessionLocal getEndEntityProfileSession() { return getEjbLocal().getEndEntityProfileSession(); }
	@Override public GlobalConfigurationSessionLocal getGlobalConfigurationSession() { return getEjbLocal().getGlobalConfigurationSession(); }
	@Override public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() { return getEjbLocal().getHardTokenBatchJobSession(); }
	@Override public HardTokenSessionLocal getHardTokenSession() { return getEjbLocal().getHardTokenSession(); }
	@Override public KeyRecoverySessionLocal getKeyRecoverySession() { return getEjbLocal().getKeyRecoverySession(); }
	@Override public LogSessionLocal getLogSession() { return getEjbLocal().getLogSession(); }
	@Override public LogConfigurationSessionLocal getLogConfigurationSession() { return getEjbLocal().getLogConfigurationSession(); }
	@Override public UserAdminSessionLocal getUserAdminSession() { return getEjbLocal().getUserAdminSession(); }
	@Override public RaAdminSessionLocal getRaAdminSession() { return getEjbLocal().getRaAdminSession(); }
	@Override public OldLogSessionLocal getOldLogSession() { return getEjbLocal().getOldLogSession(); }
	@Override public PublisherQueueSessionLocal getPublisherQueueSession() { return getEjbLocal().getPublisherQueueSession(); }
	@Override public PublisherSessionLocal getPublisherSession() { return getEjbLocal().getPublisherSession(); }
	@Override public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() { return getEjbLocal().getSecurityEventsAuditorSession(); }
	@Override public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() { return getEjbLocal().getSecurityEventsLoggerSession(); }
	@Override public ServiceSessionLocal getServiceSession() { return getEjbLocal().getServiceSession(); }
	@Override public SignSessionLocal getSignSession() { return getEjbLocal().getSignSession(); }
	@Override public CertificateCreateSessionLocal getCertificateCreateSession() { return getEjbLocal().getCertificateCreateSession(); }
	@Override public UserDataSourceSessionLocal getUserDataSourceSession() { return getEjbLocal().getUserDataSourceSession(); }
	
	//TODO: Temporary mock
	@Deprecated @Override public SimpleAuthenticationProviderLocal getSimpleAuthenticationProvider() { return getEjbLocal().getSimpleAuthenticationProvider(); }
}