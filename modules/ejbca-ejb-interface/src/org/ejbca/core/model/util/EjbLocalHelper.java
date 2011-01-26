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

import org.cesecore.core.ejb.authorization.AdminEntitySession;
import org.cesecore.core.ejb.authorization.AdminGroupSession;
import org.cesecore.core.ejb.ca.crl.CrlCreateSession;
import org.cesecore.core.ejb.ca.crl.CrlSession;
import org.cesecore.core.ejb.ca.store.CertificateProfileSession;
import org.cesecore.core.ejb.log.LogSession;
import org.cesecore.core.ejb.log.OldLogSession;
import org.cesecore.core.ejb.ra.raadmin.EndEntityProfileSession;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSession;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.auth.AuthenticationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CaSession;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.hardtoken.HardTokenBatchJobSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSession;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.ejb.services.ServiceSession;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSession;

/**
 * Helper methods to get EJB session interfaces.
 * 
 * @version $Id$
 */
public class EjbLocalHelper {
	
	EjbBridgeSessionLocal ejbLocalBridgeSession = null;
	static Context initialContext = null;
	static ReentrantLock initialContextLock = new ReentrantLock(true);
	
	Context getInitialContext() throws NamingException {
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
	 * Requires a "ejb-local-ref" definition in web.xml and ejb-jar.xml from all accessing components.
	 * @return a reference to the bridge SSB
	 */
	EjbBridgeSessionLocal getEjbLocal() {
		try {
			return (EjbBridgeSessionLocal) getInitialContext().lookup("java:comp/env/EjbBridgeSession");
		} catch (NamingException e) {
			throw new RuntimeException("A ejb-local-ref declaration in ejb-jar.xml or web.xml is missing.", e);
		}
	}

	public AdminEntitySession getAdminEntitySession() { return getEjbLocal().getAdminEntitySession(); }
	public AdminGroupSession getAdminGroupSession() { return getEjbLocal().getAdminGroupSession(); }
    public SignSession getSignSession() { return getEjbLocal().getSignSession(); }
    public CaSession getCaSession() { return getEjbLocal().getCaSession(); }
    public CAAdminSession getCAAdminSession() { return getEjbLocal().getCaAdminSession(); }
    public AuthenticationSession getAuthenticationSession() { return getEjbLocal().getAuthenticationSession(); }
    public AuthorizationSession getAuthorizationSession()  { return getEjbLocal().getAuthorizationSession(); }
    public CrlCreateSession getCrlCreateSession() { return getEjbLocal().getCrlStoreSession(); }
    public KeyRecoverySession getKeyRecoverySession() { return getEjbLocal().getKeyRecoverySession(); }
    public CertificateProfileSession getCertificateProfileSession() { return getEjbLocal().getCertificateProfileSession(); }
	public CertificateStoreSession getCertStoreSession() { return getEjbLocal().getCertificateStoreSession(); }
	public EndEntityProfileSession getEndEntityProfileSession() { return getEjbLocal().getEndEntityProfileSession(); }
	public UserAdminSession getUserAdminSession() { return getEjbLocal().getUserSession(); }
	public RaAdminSession getRAAdminSession() { return getEjbLocal().getRaSession(); }
	public ApprovalSession getApprovalSession() { return getEjbLocal().getApprovalSession(); }
	public HardTokenSession getHardTokenSession() { return getEjbLocal().getHardtokenSession(); }
	public LogSession getLogSession() { return getEjbLocal().getLogSession(); }
	public OldLogSession getOldLogSession() { return getEjbLocal().getOldLogSession(); }
	public PublisherQueueSession getPublisherQueueSession() { return getEjbLocal().getPublisherQueueSession(); }
	public UserDataSourceSession getUserDataSourceSession() { return getEjbLocal().getUserDataSourceSession(); }
	public CrlSession getCreateCrlSession() { return getEjbLocal().getCreateCRLSession(); }
	public PublisherSession getPublisherSession() { return getEjbLocal().getPublisherSession(); }
	public ServiceSession getServiceSession() { return getEjbLocal().getServiceSession(); }
	public HardTokenBatchJobSession getHardTokenBatchSession() { return getEjbLocal().getHardTokenBatchJobSession(); }
	public CmpMessageDispatcherSession getCmpMessageDispatcherSession() { return getEjbLocal().getCmpMessageDispatcherSession(); }
}