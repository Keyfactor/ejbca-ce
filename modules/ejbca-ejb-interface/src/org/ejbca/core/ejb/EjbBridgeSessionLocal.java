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

import javax.ejb.Local;

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
@Local
public interface EjbBridgeSessionLocal {

    AdminPreferenceSessionLocal getAdminPreferenceSession();
	ApprovalExecutionSessionLocal getApprovalExecutionSession();
	ApprovalProfileSessionLocal getApprovalProfileSession();
	ApprovalSessionLocal getApprovalSession();
    AuthorizationSessionLocal getAuthorizationSession();
    AuthorizationSystemSessionLocal getAuthorizationSystemSession();
	BlacklistSessionLocal getBlacklistSession();
	CAAdminSessionLocal getCaAdminSession();
	CaSessionLocal getCaSession();
	CertificateCreateSessionLocal getCertificateCreateSession();
	CertificateProfileSessionLocal getCertificateProfileSession();
	CertificateStoreSessionLocal getCertificateStoreSession();
	CertReqHistorySessionLocal getCertReqHistorySession();
	CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession();
	CrlCreateSessionLocal getCrlCreateSession();
    CrlStoreSessionLocal getCrlStoreSession();
	CryptoTokenManagementSessionLocal getCryptoTokenManagementSession();
	CryptoTokenSessionLocal getCryptoTokenSession();
	EjbcaAuditorSessionLocal getEjbcaAuditorSession();
	EjbcaRestHelperSessionLocal getEjbcaRestHelperSession();
	EjbcaWSHelperSessionLocal getEjbcaWSHelperSession();
	EndEntityAccessSessionLocal getEndEntityAccessSession();
	EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession();
	EndEntityManagementSessionLocal getEndEntityManagementSession();
	EndEntityProfileSessionLocal getEndEntityProfileSession();
	GlobalConfigurationSessionLocal getGlobalConfigurationSession();
    ImportCrlSessionLocal getImportCrlSession();
    InternalKeyBindingDataSessionLocal getInternalKeyBindingDataSession();
    InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession();
    KeyRecoverySessionLocal getKeyRecoverySession();
	KeyValidatorSessionLocal getKeyValidatorSession();
	PublisherQueueSessionLocal getPublisherQueueSession();
	PublisherSessionLocal getPublisherSession();
	PublishingCrlSessionLocal getPublishingCrlSession();
    RaMasterApiProxyBeanLocal getRaMasterApiProxyBean();
	RaMasterApiSessionLocal getRaMasterApiSession();
	RevocationSessionLocal getRevocationSession();
	RoleDataSessionLocal getRoleDataSession();
	RoleMemberDataSessionLocal getRoleMemberDataSession();
	RoleMemberSessionLocal getRoleMemberSession();
    RoleSessionLocal getRoleSession();
    SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession();
    SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession();
    ServiceSessionLocal getServiceSession();
    SignSessionLocal getSignSession();
    UpgradeSessionLocal getUpgradeSession();
    UserDataSourceSessionLocal getUserDataSourceSession();
    WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession();
}
