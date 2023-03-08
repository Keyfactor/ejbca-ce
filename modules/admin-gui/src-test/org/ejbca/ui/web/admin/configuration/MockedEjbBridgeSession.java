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
package org.ejbca.ui.web.admin.configuration;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.lang.math.IntRange;
import org.cesecore.audit.audit.SecurityEventsAuditorSessionLocal;
import org.cesecore.audit.log.SecurityEventsLoggerSessionLocal;
import org.cesecore.authorization.AuthorizationSessionLocal;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.CertificateCreateSessionLocal;
import org.cesecore.certificates.certificate.CertificateStoreSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.certificates.certificatetransparency.SctDataSessionLocal;
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
import org.easymock.EasyMock;
import org.ejbca.core.ejb.EjbBridgeSessionLocal;
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
import org.ejbca.core.ejb.config.ClearCacheSessionLocal;
import org.ejbca.core.ejb.crl.ImportCrlSessionLocal;
import org.ejbca.core.ejb.crl.PublishingCrlSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionLocal;
import org.ejbca.core.ejb.ocsp.OcspDataSessionLocal;
import org.ejbca.core.ejb.ocsp.OcspResponseCleanupSessionLocal;
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
 * Mocked clalss
 */
public class MockedEjbBridgeSession implements EjbBridgeSessionLocal {

    /*
       The code below was generated with a little shell script. The name of getCaAdminSession needs to be manually modified.
       (you need to put the getters from EjbBridgeSessionLocal in a text file called sessions.txt)
       
-----BEGIN SHELL SCRIPT-----
#!/bin/sh -eu

list_sessions() {
    cut -d ' ' -f 1 sessions_raw.txt
}

lowercase_first() {
    first_lowercase=$(echo "$session" | cut -c 1-1 | tr '[:upper:]' '[:lower:]')
    following=$(echo "$session" | cut -c 2-)
    echo "$first_lowercase$following"
}

list_sessions | while read classname; do
    session=${classname%Local}
    fieldname=$(lowercase_first "$session")
    echo "    private $classname $fieldname;" 
done

echo

list_sessions | while read classname; do
    session=${classname%Local}
    fieldname=$(lowercase_first "$session")
cat <<EOF 
    @Override public synchronized $classname get$session() { 
        if ($fieldname == null) { $fieldname = EasyMock.createStrictMock($classname.class); }
        return $fieldname; 
    }
EOF
done

echo

echo "    public List<Object> getAllMockObjects() {"
echo "        final List<Object> list = new ArrayList<>();"
list_sessions | while read classname; do
    session=${classname%Local}
    fieldname=$(lowercase_first "$session")
    echo "        list.add($fieldname);"
done
echo "        return list.stream().filter(x -> x != null).collect(Collectors.toList());"
echo "    }"
-----END SHELL SCRIPT-----
     
     */
    
    private AdminPreferenceSessionLocal adminPreferenceSession;
    private ApprovalExecutionSessionLocal approvalExecutionSession;
    private ApprovalProfileSessionLocal approvalProfileSession;
    private ApprovalSessionLocal approvalSession;
    private AuthorizationSessionLocal authorizationSession;
    private AuthorizationSystemSessionLocal authorizationSystemSession;
    private BlacklistSessionLocal blacklistSession;
    private CAAdminSessionLocal cAAdminSession;
    private CaSessionLocal caSession;
    private CertificateCreateSessionLocal certificateCreateSession;
    private CertificateProfileSessionLocal certificateProfileSession;
    private CertificateStoreSessionLocal certificateStoreSession;
    private CertReqHistorySessionLocal certReqHistorySession;
    private ClearCacheSessionLocal clearCacheSession;
    private CmpMessageDispatcherSessionLocal cmpMessageDispatcherSession;
    private CrlCreateSessionLocal crlCreateSession;
    private CrlStoreSessionLocal crlStoreSession;
    private CryptoTokenManagementSessionLocal cryptoTokenManagementSession;
    private CryptoTokenSessionLocal cryptoTokenSession;
    private EjbcaAuditorSessionLocal ejbcaAuditorSession;
    private EjbcaRestHelperSessionLocal ejbcaRestHelperSession;
    private EjbcaWSHelperSessionLocal ejbcaWSHelperSession;
    private EndEntityAccessSessionLocal endEntityAccessSession;
    private EndEntityAuthenticationSessionLocal endEntityAuthenticationSession;
    private EndEntityManagementSessionLocal endEntityManagementSession;
    private EndEntityProfileSessionLocal endEntityProfileSession;
    private GlobalConfigurationSessionLocal globalConfigurationSession;
    private ImportCrlSessionLocal importCrlSession;
    private InternalKeyBindingDataSessionLocal internalKeyBindingDataSession;
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;
    private KeyRecoverySessionLocal keyRecoverySession;
    private KeyValidatorSessionLocal keyValidatorSession;
    private PublisherQueueSessionLocal publisherQueueSession;
    private PublisherSessionLocal publisherSession;
    private PublishingCrlSessionLocal publishingCrlSession;
    private RaMasterApiProxyBeanLocal raMasterApiProxyBean;
    private RaMasterApiSessionLocal raMasterApiSession;
    private RevocationSessionLocal revocationSession;
    private RoleDataSessionLocal roleDataSession;
    private RoleMemberDataSessionLocal roleMemberDataSession;
    private RoleMemberSessionLocal roleMemberSession;
    private RoleSessionLocal roleSession;
    private SecurityEventsAuditorSessionLocal securityEventsAuditorSession;
    private SecurityEventsLoggerSessionLocal securityEventsLoggerSession;
    private ServiceSessionLocal serviceSession;
    private SignSessionLocal signSession;
    private UpgradeSessionLocal upgradeSession;
    private UserDataSourceSessionLocal userDataSourceSession;
    private WebAuthenticationProviderSessionLocal webAuthenticationProviderSession;
    private SctDataSessionLocal sctDataSession;
    private OcspDataSessionLocal ocspDataSession;
    private OcspResponseCleanupSessionLocal ocspResponseCleanupSession;

    @Override public synchronized AdminPreferenceSessionLocal getAdminPreferenceSession() {
        if (adminPreferenceSession == null) { adminPreferenceSession = EasyMock.createStrictMock(AdminPreferenceSessionLocal.class); }
        return adminPreferenceSession;
    }
    @Override public synchronized ApprovalExecutionSessionLocal getApprovalExecutionSession() {
        if (approvalExecutionSession == null) { approvalExecutionSession = EasyMock.createStrictMock(ApprovalExecutionSessionLocal.class); }
        return approvalExecutionSession;
    }
    @Override public synchronized ApprovalProfileSessionLocal getApprovalProfileSession() {
        if (approvalProfileSession == null) { approvalProfileSession = EasyMock.createStrictMock(ApprovalProfileSessionLocal.class); }
        return approvalProfileSession;
    }
    @Override public synchronized ApprovalSessionLocal getApprovalSession() {
        if (approvalSession == null) { approvalSession = EasyMock.createStrictMock(ApprovalSessionLocal.class); }
        return approvalSession;
    }
    @Override public synchronized AuthorizationSessionLocal getAuthorizationSession() {
        if (authorizationSession == null) { authorizationSession = EasyMock.createStrictMock(AuthorizationSessionLocal.class); }
        return authorizationSession;
    }
    @Override public synchronized AuthorizationSystemSessionLocal getAuthorizationSystemSession() {
        if (authorizationSystemSession == null) { authorizationSystemSession = EasyMock.createStrictMock(AuthorizationSystemSessionLocal.class); }
        return authorizationSystemSession;
    }
    @Override public synchronized BlacklistSessionLocal getBlacklistSession() {
        if (blacklistSession == null) { blacklistSession = EasyMock.createStrictMock(BlacklistSessionLocal.class); }
        return blacklistSession;
    }
    @Override public synchronized CAAdminSessionLocal getCaAdminSession() {
        if (cAAdminSession == null) { cAAdminSession = EasyMock.createStrictMock(CAAdminSessionLocal.class); }
        return cAAdminSession;
    }
    @Override public synchronized CaSessionLocal getCaSession() {
        if (caSession == null) { caSession = EasyMock.createStrictMock(CaSessionLocal.class); }
        return caSession;
    }
    @Override public synchronized CertificateCreateSessionLocal getCertificateCreateSession() {
        if (certificateCreateSession == null) { certificateCreateSession = EasyMock.createStrictMock(CertificateCreateSessionLocal.class); }
        return certificateCreateSession;
    }
    @Override public synchronized CertificateProfileSessionLocal getCertificateProfileSession() {
        if (certificateProfileSession == null) { certificateProfileSession = EasyMock.createStrictMock(CertificateProfileSessionLocal.class); }
        return certificateProfileSession;
    }
    @Override public synchronized CertificateStoreSessionLocal getCertificateStoreSession() {
        if (certificateStoreSession == null) { certificateStoreSession = EasyMock.createStrictMock(CertificateStoreSessionLocal.class); }
        return certificateStoreSession;
    }
    @Override public synchronized CertReqHistorySessionLocal getCertReqHistorySession() {
        if (certReqHistorySession == null) { certReqHistorySession = EasyMock.createStrictMock(CertReqHistorySessionLocal.class); }
        return certReqHistorySession;
    }
    @Override public synchronized ClearCacheSessionLocal getClearCacheSession() {
        if (clearCacheSession == null) { clearCacheSession = EasyMock.createStrictMock(ClearCacheSessionLocal.class); }
        return clearCacheSession;
    }
    @Override public synchronized CmpMessageDispatcherSessionLocal getCmpMessageDispatcherSession() {
        if (cmpMessageDispatcherSession == null) { cmpMessageDispatcherSession = EasyMock.createStrictMock(CmpMessageDispatcherSessionLocal.class); }
        return cmpMessageDispatcherSession;
    }
    @Override public synchronized CrlCreateSessionLocal getCrlCreateSession() {
        if (crlCreateSession == null) { crlCreateSession = EasyMock.createStrictMock(CrlCreateSessionLocal.class); }
        return crlCreateSession;
    }
    @Override public synchronized CrlStoreSessionLocal getCrlStoreSession() {
        if (crlStoreSession == null) { crlStoreSession = EasyMock.createStrictMock(CrlStoreSessionLocal.class); }
        return crlStoreSession;
    }
    @Override public synchronized CryptoTokenManagementSessionLocal getCryptoTokenManagementSession() {
        if (cryptoTokenManagementSession == null) { cryptoTokenManagementSession = EasyMock.createStrictMock(CryptoTokenManagementSessionLocal.class); }
        return cryptoTokenManagementSession;
    }
    @Override public synchronized CryptoTokenSessionLocal getCryptoTokenSession() {
        if (cryptoTokenSession == null) { cryptoTokenSession = EasyMock.createStrictMock(CryptoTokenSessionLocal.class); }
        return cryptoTokenSession;
    }
    @Override public synchronized EjbcaAuditorSessionLocal getEjbcaAuditorSession() {
        if (ejbcaAuditorSession == null) { ejbcaAuditorSession = EasyMock.createStrictMock(EjbcaAuditorSessionLocal.class); }
        return ejbcaAuditorSession;
    }
    @Override public synchronized EjbcaRestHelperSessionLocal getEjbcaRestHelperSession() {
        if (ejbcaRestHelperSession == null) { ejbcaRestHelperSession = EasyMock.createStrictMock(EjbcaRestHelperSessionLocal.class); }
        return ejbcaRestHelperSession;
    }
    @Override public synchronized EndEntityAccessSessionLocal getEndEntityAccessSession() {
        if (endEntityAccessSession == null) { endEntityAccessSession = EasyMock.createStrictMock(EndEntityAccessSessionLocal.class); }
        return endEntityAccessSession;
    }
    @Override public synchronized EndEntityAuthenticationSessionLocal getEndEntityAuthenticationSession() {
        if (endEntityAuthenticationSession == null) { endEntityAuthenticationSession = EasyMock.createStrictMock(EndEntityAuthenticationSessionLocal.class); }
        return endEntityAuthenticationSession;
    }
    @Override public synchronized EndEntityManagementSessionLocal getEndEntityManagementSession() {
        if (endEntityManagementSession == null) { endEntityManagementSession = EasyMock.createStrictMock(EndEntityManagementSessionLocal.class); }
        return endEntityManagementSession;
    }
    @Override public synchronized EndEntityProfileSessionLocal getEndEntityProfileSession() {
        if (endEntityProfileSession == null) { endEntityProfileSession = EasyMock.createStrictMock(EndEntityProfileSessionLocal.class); }
        return endEntityProfileSession;
    }
    @Override public synchronized GlobalConfigurationSessionLocal getGlobalConfigurationSession() {
        if (globalConfigurationSession == null) { globalConfigurationSession = EasyMock.createStrictMock(GlobalConfigurationSessionLocal.class); }
        return globalConfigurationSession;
    }
    @Override public synchronized ImportCrlSessionLocal getImportCrlSession() {
        if (importCrlSession == null) { importCrlSession = EasyMock.createStrictMock(ImportCrlSessionLocal.class); }
        return importCrlSession;
    }
    @Override public synchronized InternalKeyBindingDataSessionLocal getInternalKeyBindingDataSession() {
        if (internalKeyBindingDataSession == null) { internalKeyBindingDataSession = EasyMock.createStrictMock(InternalKeyBindingDataSessionLocal.class); }
        return internalKeyBindingDataSession;
    }
    @Override public synchronized InternalKeyBindingMgmtSessionLocal getInternalKeyBindingMgmtSession() {
        if (internalKeyBindingMgmtSession == null) { internalKeyBindingMgmtSession = EasyMock.createStrictMock(InternalKeyBindingMgmtSessionLocal.class); }
        return internalKeyBindingMgmtSession;
    }
    @Override public synchronized KeyRecoverySessionLocal getKeyRecoverySession() {
        if (keyRecoverySession == null) { keyRecoverySession = EasyMock.createStrictMock(KeyRecoverySessionLocal.class); }
        return keyRecoverySession;
    }
    @Override public synchronized KeyValidatorSessionLocal getKeyValidatorSession() {
        if (keyValidatorSession == null) { keyValidatorSession = EasyMock.createStrictMock(KeyValidatorSessionLocal.class); }
        return keyValidatorSession;
    }
    @Override public synchronized PublisherQueueSessionLocal getPublisherQueueSession() {
        if (publisherQueueSession == null) { publisherQueueSession = EasyMock.createStrictMock(PublisherQueueSessionLocal.class); }
        return publisherQueueSession;
    }
    @Override public synchronized PublisherSessionLocal getPublisherSession() {
        if (publisherSession == null) { publisherSession = EasyMock.createStrictMock(PublisherSessionLocal.class); }
        return publisherSession;
    }
    @Override public synchronized PublishingCrlSessionLocal getPublishingCrlSession() {
        if (publishingCrlSession == null) { publishingCrlSession = EasyMock.createStrictMock(PublishingCrlSessionLocal.class); }
        return publishingCrlSession;
    }
    @Override public synchronized RaMasterApiProxyBeanLocal getRaMasterApiProxyBean() {
        if (raMasterApiProxyBean == null) { raMasterApiProxyBean = EasyMock.createStrictMock(RaMasterApiProxyBeanLocal.class); }
        return raMasterApiProxyBean;
    }
    @Override public synchronized RaMasterApiSessionLocal getRaMasterApiSession() {
        if (raMasterApiSession == null) { raMasterApiSession = EasyMock.createStrictMock(RaMasterApiSessionLocal.class); }
        return raMasterApiSession;
    }
    @Override public synchronized RevocationSessionLocal getRevocationSession() {
        if (revocationSession == null) { revocationSession = EasyMock.createStrictMock(RevocationSessionLocal.class); }
        return revocationSession;
    }
    @Override public synchronized RoleDataSessionLocal getRoleDataSession() {
        if (roleDataSession == null) { roleDataSession = EasyMock.createStrictMock(RoleDataSessionLocal.class); }
        return roleDataSession;
    }
    @Override public synchronized RoleMemberDataSessionLocal getRoleMemberDataSession() {
        if (roleMemberDataSession == null) { roleMemberDataSession = EasyMock.createStrictMock(RoleMemberDataSessionLocal.class); }
        return roleMemberDataSession;
    }
    @Override public synchronized RoleMemberSessionLocal getRoleMemberSession() {
        if (roleMemberSession == null) { roleMemberSession = EasyMock.createStrictMock(RoleMemberSessionLocal.class); }
        return roleMemberSession;
    }
    @Override public synchronized RoleSessionLocal getRoleSession() {
        if (roleSession == null) { roleSession = EasyMock.createStrictMock(RoleSessionLocal.class); }
        return roleSession;
    }
    @Override public synchronized SecurityEventsAuditorSessionLocal getSecurityEventsAuditorSession() {
        if (securityEventsAuditorSession == null) { securityEventsAuditorSession = EasyMock.createStrictMock(SecurityEventsAuditorSessionLocal.class); }
        return securityEventsAuditorSession;
    }
    @Override public synchronized SecurityEventsLoggerSessionLocal getSecurityEventsLoggerSession() {
        if (securityEventsLoggerSession == null) { securityEventsLoggerSession = EasyMock.createStrictMock(SecurityEventsLoggerSessionLocal.class); }
        return securityEventsLoggerSession;
    }
    @Override public synchronized ServiceSessionLocal getServiceSession() {
        if (serviceSession == null) { serviceSession = EasyMock.createStrictMock(ServiceSessionLocal.class); }
        return serviceSession;
    }
    @Override public synchronized SignSessionLocal getSignSession() {
        if (signSession == null) { signSession = EasyMock.createStrictMock(SignSessionLocal.class); }
        return signSession;
    }
    @Override public synchronized UpgradeSessionLocal getUpgradeSession() {
        if (upgradeSession == null) { upgradeSession = EasyMock.createStrictMock(UpgradeSessionLocal.class); }
        return upgradeSession;
    }
    @Override public synchronized UserDataSourceSessionLocal getUserDataSourceSession() {
        if (userDataSourceSession == null) { userDataSourceSession = EasyMock.createStrictMock(UserDataSourceSessionLocal.class); }
        return userDataSourceSession;
    }
    @Override public synchronized WebAuthenticationProviderSessionLocal getWebAuthenticationProviderSession() {
        if (webAuthenticationProviderSession == null) { webAuthenticationProviderSession = EasyMock.createStrictMock(WebAuthenticationProviderSessionLocal.class); }
        return webAuthenticationProviderSession;
    }
    @Override public synchronized SctDataSessionLocal getSctDataSession() {
        if (sctDataSession == null) { sctDataSession = EasyMock.createStrictMock(SctDataSessionLocal.class); }
        return sctDataSession;
    }
    @Override public synchronized OcspDataSessionLocal getOcspDataSession() {
        if (ocspDataSession == null) { ocspDataSession = EasyMock.createStrictMock(OcspDataSessionLocal.class); }
        return ocspDataSession;
    }
    @Override public synchronized OcspResponseCleanupSessionLocal getOcspResponseCleanupSession() {
        if (ocspResponseCleanupSession == null) { ocspResponseCleanupSession = EasyMock.createStrictMock(OcspResponseCleanupSessionLocal.class); }
        return ocspResponseCleanupSession;
    }

    public List<Object> getAllMockObjects() {
        final List<Object> list = new ArrayList<>();
        list.add(adminPreferenceSession);
        list.add(approvalExecutionSession);
        list.add(approvalProfileSession);
        list.add(approvalSession);
        list.add(authorizationSession);
        list.add(authorizationSystemSession);
        list.add(blacklistSession);
        list.add(cAAdminSession);
        list.add(caSession);
        list.add(certificateCreateSession);
        list.add(certificateProfileSession);
        list.add(certificateStoreSession);
        list.add(certReqHistorySession);
        list.add(clearCacheSession);
        list.add(cmpMessageDispatcherSession);
        list.add(crlCreateSession);
        list.add(crlStoreSession);
        list.add(cryptoTokenManagementSession);
        list.add(cryptoTokenSession);
        list.add(ejbcaAuditorSession);
        list.add(ejbcaRestHelperSession);
        list.add(ejbcaWSHelperSession);
        list.add(endEntityAccessSession);
        list.add(endEntityAuthenticationSession);
        list.add(endEntityManagementSession);
        list.add(endEntityProfileSession);
        list.add(globalConfigurationSession);
        list.add(importCrlSession);
        list.add(internalKeyBindingDataSession);
        list.add(internalKeyBindingMgmtSession);
        list.add(keyRecoverySession);
        list.add(keyValidatorSession);
        list.add(publisherQueueSession);
        list.add(publisherSession);
        list.add(publishingCrlSession);
        list.add(raMasterApiProxyBean);
        list.add(raMasterApiSession);
        list.add(revocationSession);
        list.add(roleDataSession);
        list.add(roleMemberDataSession);
        list.add(roleMemberSession);
        list.add(roleSession);
        list.add(securityEventsAuditorSession);
        list.add(securityEventsLoggerSession);
        list.add(serviceSession);
        list.add(signSession);
        list.add(upgradeSession);
        list.add(userDataSourceSession);
        list.add(webAuthenticationProviderSession);
        list.add(sctDataSession);
        list.add(ocspDataSession);
        list.add(ocspResponseCleanupSession);
        return list.stream().filter(x -> x != null).collect(Collectors.toList());
    }
    
}
