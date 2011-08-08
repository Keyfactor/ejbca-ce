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

package org.ejbca.core.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

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
import org.cesecore.mock.authentication.SimpleAuthenticationProviderLocal;
import org.cesecore.roles.access.RoleAccessSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
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
 * Due to the lack of standardization in JEE5 there is no way to lookup local interfaces.
 * 
 * This Stateless Session Bean (SSB) act as a bridge between calling classes in the same JVM,
 * and the real ejb references.
 * 
 * This will allow us to define a single (this) local EJB in all web.xml and ejb-jar.xml files
 * and are then free to change and move around SSBs and their interfaces without XML changes.
 * 
 * @version $Id$
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EjbBridgeSessionBean implements EjbBridgeSessionLocal {

	@EJB AdminEntitySessionLocal adminEntitySession;	
	@EJB ApprovalExecutionSessionLocal approvalExecutionSession;
	@EJB ApprovalSessionLocal approvalSession;
	@EJB AccessControlSessionLocal authorizationSession;
	@EJB AuthenticationSessionLocal authenticationSession;
	@EJB OldAuthenticationSessionLocal oldAuthenticationSession;
	@EJB CAAdminSessionLocal caAdminSession;
	@EJB CaSessionLocal caSession;
	@EJB CertificateProfileSessionLocal certificateProfileSession;
	@EJB CertificateStoreSessionLocal certificateStoreSession;
	@EJB CertReqHistorySessionLocal certReqHistorySession;
	@EJB CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
	@EJB CrlStoreSessionLocal crlStoreSession;
	@EJB CrlCreateSessionLocal crlCreateSession;
	@EJB CertificateCreateSessionLocal certificateCreateSession;
	@EJB EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB GlobalConfigurationSessionLocal globalConfigurationSession;
	@EJB HardTokenBatchJobSessionLocal hardTokenBatchJobSession;
	@EJB HardTokenSessionLocal hardTokenSession;
	@EJB KeyRecoverySessionLocal keyRecoverySession;
	@EJB LogSessionLocal logSession;
	@EJB LogConfigurationSessionLocal logConfigurationSession;
	@EJB OldLogSessionLocal oldLogSession;
	@EJB PublisherQueueSessionLocal publisherQueueSession;
	@EJB PublisherSessionLocal publisherSession;
	@EJB RaAdminSessionLocal raSession;
	@EJB RoleAccessSessionLocal roleAccessSession;
	@EJB SecurityEventsAuditorSessionLocal securityEventsAuditorSession;
	@EJB SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
	@EJB ServiceSessionLocal serviceSession;
	@EJB SignSessionLocal signSession;
	@EJB UserDataSourceSessionLocal userDataSourceSession;
	@EJB UserAdminSessionLocal userAdminSession;
	@EJB RevocationSessionLocal revocationSession;
	
	@EJB SimpleAuthenticationProviderLocal simpleAuthenticationProvider;

	@Override public AdminEntitySessionLocal getAdminEntitySession() { return adminEntitySession; }	
	@Override public ApprovalExecutionSessionLocal getApprovalExecutionSession() { return approvalExecutionSession; }
	@Override public ApprovalSessionLocal getApprovalSession() { return approvalSession; }
	@Override public AccessControlSessionLocal getAccessControlSession() { return authorizationSession; }
	@Override public AuthenticationSessionLocal getAuthenticationSession() { return authenticationSession; }
	@Override public OldAuthenticationSessionLocal getOldAuthenticationSession() { return oldAuthenticationSession; }
	@Override public CAAdminSessionLocal getCaAdminSession() { return caAdminSession; }
	@Override public CaSessionLocal getCaSession() { return caSession; }
	@Override public CertificateProfileSessionLocal getCertificateProfileSession() { return certificateProfileSession; }
	@Override public CertificateStoreSessionLocal getCertificateStoreSession() { return certificateStoreSession; }
	@Override public CertReqHistorySessionLocal getCertReqHistorySession() { return certReqHistorySession; }
	@Override public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return cmpMessageDispatcherSession; }
	@Override public CrlStoreSessionLocal getCrlStoreSession() { return crlStoreSession; }
	@Override public CrlCreateSessionLocal getCrlCreateSession() { return crlCreateSession; }
	@Override public CertificateCreateSessionLocal getCertificateCreateSession() { return certificateCreateSession; }
	@Override public EndEntityProfileSessionLocal getEndEntityProfileSession() { return endEntityProfileSession; }
	@Override public GlobalConfigurationSessionLocal getGlobalConfigurationSession() { return globalConfigurationSession; }
	@Override public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() { return hardTokenBatchJobSession; }
	@Override public HardTokenSessionLocal getHardTokenSession() { return hardTokenSession; }
	@Override public KeyRecoverySessionLocal getKeyRecoverySession() { return keyRecoverySession; }
	@Override public LogSessionLocal getLogSession() { return logSession; }
	@Override public OldLogSessionLocal getOldLogSession() { return oldLogSession; }
	@Override public PublisherQueueSessionLocal getPublisherQueueSession() { return publisherQueueSession; }
	@Override public PublisherSessionLocal getPublisherSession() { return publisherSession; }
	@Override public RaAdminSessionLocal getRaAdminSession() { return raSession; }
	@Override public RevocationSessionLocal getRevocationSession() { return revocationSession; }
	@Override public RoleAccessSessionLocal getRoleAccessSession() { return roleAccessSession; }
	@Override public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() { return securityEventsAuditorSession; }
	@Override public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() { return securityEventsLoggerSession; }
	@Override public ServiceSessionLocal getServiceSession() { return serviceSession; }
	@Override public SignSessionLocal getSignSession() { return signSession; }
	@Override public UserDataSourceSessionLocal getUserDataSourceSession() { return userDataSourceSession; }
	@Override public UserAdminSessionLocal getUserAdminSession() { return userAdminSession; }
	@Override public LogConfigurationSessionLocal getLogConfigurationSession() { return logConfigurationSession; }
	
	

    @Override
    public SimpleAuthenticationProviderLocal getSimpleAuthenticationProvider() { return simpleAuthenticationProvider; }
}
