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

package org.ejbca.core.ejb;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
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
import org.cesecore.roles.management.RoleManagementSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.EjbcaAuditorSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.ComplexAccessControlSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
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
	
	@EJB ApprovalExecutionSessionLocal approvalExecutionSession;
	@EJB ApprovalSessionLocal approvalSession;
	@EJB ApprovalProfileSessionLocal approvalProfileSession;
	@EJB AccessControlSessionLocal authorizationSession;
	@EJB AccessRuleManagementSessionLocal accessRuleManagementSession;
	@EJB CAAdminSessionLocal caAdminSession;
	@EJB CaSessionLocal caSession;
	@EJB CertificateProfileSessionLocal certificateProfileSession;
	@EJB CertificateStoreSessionLocal certificateStoreSession;
	@EJB CertReqHistorySessionLocal certReqHistorySession;
	@EJB CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
	@EJB ComplexAccessControlSessionLocal complexAccessControlSession;
	@EJB CrlStoreSessionLocal crlStoreSession;
	@EJB CrlCreateSessionLocal crlCreateSession;
	@EJB CertificateCreateSessionLocal certificateCreateSession;
	@EJB EjbcaAuditorSessionLocal ejbcaAuditorSession;
	@EJB EndEntityAccessSessionLocal endEntityAccessSession;
	@EJB EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB GlobalConfigurationSessionLocal globalConfigurationSession;
	@EJB HardTokenBatchJobSessionLocal hardTokenBatchJobSession;
	@EJB HardTokenSessionLocal hardTokenSession;
    @EJB InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
	@EJB KeyRecoverySessionLocal keyRecoverySession;
	@EJB PublisherQueueSessionLocal publisherQueueSession;
	@EJB PublisherSessionLocal publisherSession;
	@EJB AdminPreferenceSessionLocal raSession;
	@EJB RevocationSessionLocal revocationSession;
	@EJB RoleAccessSessionLocal roleAccessSession;
	@EJB RoleManagementSessionLocal roleManagementSession;
	@EJB SecurityEventsAuditorSessionLocal securityEventsAuditorSession;
	@EJB SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
	@EJB ServiceSessionLocal serviceSession;
	@EJB SignSessionLocal signSession;
    @EJB UpgradeSessionLocal upgradeSession;
	@EJB UserDataSourceSessionLocal userDataSourceSession;
	@EJB EndEntityManagementSessionLocal endEntityManagementSession;
	@EJB WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
	@EJB EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
	@EJB AccessUserAspectManagerSessionLocal accessUserAspectSession;
	@EJB CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
	@EJB PublishingCrlSessionLocal publishingCrlSessionLocal;

	@Override public ApprovalExecutionSessionLocal getApprovalExecutionSession() { return approvalExecutionSession; }
	@Override public ApprovalSessionLocal getApprovalSession() { return approvalSession; }
	@Override public ApprovalProfileSessionLocal getApprovalProfileSession() { return approvalProfileSession; }
	@Override public AccessControlSessionLocal getAccessControlSession() { return authorizationSession; }
	@Override public AccessRuleManagementSessionLocal getAccessRuleManagementSession() { return accessRuleManagementSession; }
	@Override public CAAdminSessionLocal getCaAdminSession() { return caAdminSession; }
	@Override public CaSessionLocal getCaSession() { return caSession; }
	@Override public CertificateProfileSessionLocal getCertificateProfileSession() { return certificateProfileSession; }
	@Override public CertificateStoreSessionLocal getCertificateStoreSession() { return certificateStoreSession; }
	@Override public CertReqHistorySessionLocal getCertReqHistorySession() { return certReqHistorySession; }
	@Override public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return cmpMessageDispatcherSession; }
	@Override public ComplexAccessControlSessionLocal getComplexAccessControlSession() { return complexAccessControlSession; }
	@Override public CrlStoreSessionLocal getCrlStoreSession() { return crlStoreSession; }
	@Override public CrlCreateSessionLocal getCrlCreateSession() { return crlCreateSession; }
	@Override public CertificateCreateSessionLocal getCertificateCreateSession() { return certificateCreateSession; }
	@Override public EjbcaAuditorSessionLocal getEjbcaAuditorSession() { return ejbcaAuditorSession; }
	@Override public EndEntityProfileSessionLocal getEndEntityProfileSession() { return endEntityProfileSession; }
	@Override public GlobalConfigurationSessionLocal getGlobalConfigurationSession() { return globalConfigurationSession; }
	@Override public HardTokenBatchJobSessionLocal getHardTokenBatchJobSession() { return hardTokenBatchJobSession; }
	@Override public HardTokenSessionLocal getHardTokenSession() { return hardTokenSession; }
    @Override public InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() { return internalKeyBindingMgmtSession; }
	@Override public KeyRecoverySessionLocal getKeyRecoverySession() { return keyRecoverySession; }
	@Override public PublisherQueueSessionLocal getPublisherQueueSession() { return publisherQueueSession; }
	@Override public PublisherSessionLocal getPublisherSession() { return publisherSession; }
	@Override public AdminPreferenceSessionLocal getRaAdminSession() { return raSession; }
	@Override public RevocationSessionLocal getRevocationSession() { return revocationSession; }
	@Override public RoleAccessSessionLocal getRoleAccessSession() { return roleAccessSession; }
	@Override public RoleManagementSessionLocal getRoleManagementSession() { return roleManagementSession; }
	@Override public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() { return securityEventsAuditorSession; }
	@Override public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() { return securityEventsLoggerSession; }
	@Override public ServiceSessionLocal getServiceSession() { return serviceSession; }
	@Override public SignSessionLocal getSignSession() { return signSession; }
    @Override public UpgradeSessionLocal getUpgradeSession() { return upgradeSession; }
	@Override public UserDataSourceSessionLocal getUserDataSourceSession() { return userDataSourceSession; }
	@Override public EndEntityManagementSessionLocal getEndEntityManagementSession() { return endEntityManagementSession; }
	@Override public WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession() { return webAuthenticationProviderSession; }
	@Override public EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession() { return endEntityAuthenticationSession; }
	@Override public AccessUserAspectManagerSessionLocal getAccessUserAspectSession() { return accessUserAspectSession; }
	@Override public EndEntityAccessSessionLocal getEndEntityAccessSession() { return endEntityAccessSession; }
    @Override public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() { return cryptoTokenManagementSession; }
    @Override public PublishingCrlSessionLocal getPublishingCrlSession() { return publishingCrlSessionLocal; }
}
