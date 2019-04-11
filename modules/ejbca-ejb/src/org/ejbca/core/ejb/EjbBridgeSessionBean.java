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
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.crl.CrlCreateSessionLocal;
import org.cesecore.certificates.crl.CrlStoreSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keybind.InternalKeyBindingDataSessionLocal;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keys.token.CryptoTokenManagementSessionLocal;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.cesecore.keys.validation.KeyValidatorSessionLocal;
import org.cesecore.roles.management.RoleDataSessionLocal;
import org.cesecore.roles.management.RoleSessionLocal;
import org.cesecore.roles.member.RoleMemberDataSessionLocal;
import org.cesecore.roles.member.RoleMemberSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalExecutionSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalProfileSessionLocal;
import org.ejbca.core.ejb.approval.ApprovalSessionLocal;
import org.ejbca.core.ejb.audit.EjbcaAuditorSessionLocal;
import org.ejbca.core.ejb.authentication.web.WebAuthenticationProviderSessionLocal;
import org.ejbca.core.ejb.authorization.AuthorizationSystemSessionLocal;
import org.ejbca.core.ejb.ca.auth.EndEntityAuthenticationSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSessionLocal;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionLocal;
import org.ejbca.core.ejb.ca.revoke.RevocationSessionLocal;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.ejbca.core.ejb.ca.store.CertReqHistorySessionLocal;
import org.ejbca.core.ejb.ca.validation.BlacklistSessionLocal;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionLocal;
import org.ejbca.core.ejb.rest.EjbcaRestHelperSessionLocal;
import org.ejbca.core.ejb.services.ServiceSessionLocal;
import org.ejbca.core.ejb.upgrade.UpgradeSessionLocal;
import org.ejbca.core.ejb.ws.EjbcaWSHelperSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;
import org.ejbca.core.model.era.RaMasterApiSessionLocal;
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
	
    @EJB AdminPreferenceSessionLocal adminPreferenceSession;
	@EJB ApprovalExecutionSessionLocal approvalExecutionSession;
	@EJB ApprovalProfileSessionLocal approvalProfileSession;
	@EJB ApprovalSessionLocal approvalSession;
    @EJB AuthorizationSessionLocal authorizationSession;
    @EJB AuthorizationSystemSessionLocal authorizationSystemSession;
	@EJB BlacklistSessionLocal blacklistSession;
	@EJB CAAdminSessionLocal caAdminSession;
	@EJB CaSessionLocal caSession;
	@EJB CertificateCreateSessionLocal certificateCreateSession;
	@EJB CertificateProfileSessionLocal certificateProfileSession;
	@EJB CertificateStoreSessionLocal certificateStoreSession;
	@EJB CertReqHistorySessionLocal certReqHistorySession;
	@EJB CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
	@EJB CrlCreateSessionLocal crlCreateSession;
	@EJB CrlStoreSessionLocal crlStoreSession;
	@EJB CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
	@EJB CryptoTokenSessionLocal cryptoTokenSession;
	@EJB EjbcaAuditorSessionLocal ejbcaAuditorSession;
	@EJB EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
	@EJB EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
	@EJB EndEntityAccessSessionLocal endEntityAccessSession;
	@EJB EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    @EJB EndEntityManagementSessionLocal endEntityManagementSession;
    @EJB EndEntityProfileSessionLocal endEntityProfileSession;
	@EJB GlobalConfigurationSessionLocal globalConfigurationSession;
	@EJB ImportCrlSessionLocal importCrlSession;
	@EJB InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
	@EJB InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    @EJB KeyRecoverySessionLocal keyRecoverySession;
	@EJB KeyValidatorSessionLocal keyValidatorSession;
    @EJB PublisherQueueSessionLocal publisherQueueSession;
	@EJB PublisherSessionLocal publisherSession;
    @EJB PublishingCrlSessionLocal publishingCrlSession;
    @EJB RaMasterApiProxyBeanLocal raMasterApiProxyBean;
	@EJB RaMasterApiSessionLocal raMasterApiSession;
	@EJB RevocationSessionLocal revocationSession;
	@EJB RoleDataSessionLocal roleDataSession;
    @EJB RoleMemberDataSessionLocal roleMemberDataSession;
	@EJB RoleMemberSessionLocal roleMemberSession;
	@EJB RoleSessionLocal roleSession;
	@EJB SecurityEventsAuditorSessionLocal securityEventsAuditorSession;
	@EJB SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
	@EJB ServiceSessionLocal serviceSession;
	@EJB SignSessionLocal signSession;
	@EJB UpgradeSessionLocal upgradeSession;
	@EJB UserDataSourceSessionLocal userDataSourceSession;
	@EJB WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;

    @Override public AdminPreferenceSessionLocal getAdminPreferenceSession() { return adminPreferenceSession; }
	@Override public ApprovalExecutionSessionLocal getApprovalExecutionSession() { return approvalExecutionSession; }
	@Override public ApprovalProfileSessionLocal getApprovalProfileSession() { return approvalProfileSession; }
	@Override public ApprovalSessionLocal getApprovalSession() { return approvalSession; }
    @Override public AuthorizationSessionLocal getAuthorizationSession() { return authorizationSession; }
    @Override public AuthorizationSystemSessionLocal getAuthorizationSystemSession() { return authorizationSystemSession; }
	@Override public BlacklistSessionLocal getBlacklistSession() { return blacklistSession; }
	@Override public CAAdminSessionLocal getCaAdminSession() { return caAdminSession; }
	@Override public CaSessionLocal getCaSession() { return caSession; }
	@Override public CertificateCreateSessionLocal getCertificateCreateSession() { return certificateCreateSession; }
	@Override public CertificateProfileSessionLocal getCertificateProfileSession() { return certificateProfileSession; }
	@Override public CertificateStoreSessionLocal getCertificateStoreSession() { return certificateStoreSession; }
	@Override public CertReqHistorySessionLocal getCertReqHistorySession() { return certReqHistorySession; }
	@Override public CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() { return cmpMessageDispatcherSession; }
	@Override public CrlCreateSessionLocal getCrlCreateSession() { return crlCreateSession; }
	@Override public CrlStoreSessionLocal getCrlStoreSession() { return crlStoreSession; }
	@Override public CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() { return cryptoTokenManagementSession; }
	@Override public CryptoTokenSessionLocal getCryptoTokenSession() { return cryptoTokenSession; }
	@Override public EjbcaAuditorSessionLocal getEjbcaAuditorSession() { return ejbcaAuditorSession; }
	@Override public EjbcaRestHelperSessionLocal getEjbcaRestHelperSession() { return ejbcaRestHelperSession; }
	@Override public EjbcaWSHelperSessionLocal getEjbcaWSHelperSession() { return ejbcaWSHelperSession; }
    @Override public EndEntityAccessSessionLocal getEndEntityAccessSession() { return endEntityAccessSession; }
    @Override public EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession() { return endEntityAuthenticationSession; }
	@Override public EndEntityManagementSessionLocal getEndEntityManagementSession() { return endEntityManagementSession; }
	@Override public EndEntityProfileSessionLocal getEndEntityProfileSession() { return endEntityProfileSession; }
	@Override public GlobalConfigurationSessionLocal getGlobalConfigurationSession() { return globalConfigurationSession; }
	@Override public ImportCrlSessionLocal getImportCrlSession() { return importCrlSession; }
    @Override public InternalKeyBindingDataSessionLocal getInternalKeyBindingDataSession() { return internalKeyBindingDataSession; }
	@Override public InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() { return internalKeyBindingMgmtSession; }
    @Override public KeyRecoverySessionLocal getKeyRecoverySession() { return keyRecoverySession; }
    @Override public KeyValidatorSessionLocal getKeyValidatorSession() { return keyValidatorSession; }
    @Override public PublisherQueueSessionLocal getPublisherQueueSession() { return publisherQueueSession; }
    @Override public PublisherSessionLocal getPublisherSession() { return publisherSession; }
	@Override public PublishingCrlSessionLocal getPublishingCrlSession() { return publishingCrlSession; }
	@Override public RaMasterApiProxyBeanLocal getRaMasterApiProxyBean() { return raMasterApiProxyBean; }
	@Override public RaMasterApiSessionLocal getRaMasterApiSession() { return raMasterApiSession; }
    @Override public RevocationSessionLocal getRevocationSession() { return revocationSession; }
	@Override public RoleDataSessionLocal getRoleDataSession() { return roleDataSession; }
	@Override public RoleMemberDataSessionLocal getRoleMemberDataSession() { return roleMemberDataSession; }
	@Override public RoleMemberSessionLocal getRoleMemberSession() { return roleMemberSession; }
	@Override public RoleSessionLocal getRoleSession() { return roleSession; }
	@Override public SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() { return securityEventsAuditorSession; }
    @Override public SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() { return securityEventsLoggerSession; }
    @Override public ServiceSessionLocal getServiceSession() { return serviceSession; }
    @Override public SignSessionLocal getSignSession() { return signSession; }
    @Override public UpgradeSessionLocal getUpgradeSession() { return upgradeSession; }
    @Override public UserDataSourceSessionLocal getUserDataSourceSession() { return userDataSourceSession; }
    @Override public WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession() { return webAuthenticationProviderSession; }
}
