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
package org.ejbca.core.ejb.db;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.cesecore.authorization.cache.AccessTreeUpdateData;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.certificate.Base64CertData;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.IncompleteIssuanceJournalData;
import org.cesecore.certificates.certificate.NoConflictCertificateData;
import org.cesecore.certificates.certificateprofile.CertificateProfileData;
import org.cesecore.certificates.certificatetransparency.SctData;
import org.cesecore.certificates.crl.CRLData;
import org.cesecore.config.CesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationData;
import org.cesecore.keybind.InternalKeyBindingData;
import org.cesecore.keys.token.CryptoTokenData;
import org.cesecore.oscp.OcspResponseData;
import org.cesecore.profiles.ProfileData;
import org.cesecore.roles.AdminGroupData;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.member.RoleMemberData;
import org.ejbca.acme.AcmeAccountData;
import org.ejbca.acme.AcmeAuthorizationData;
import org.ejbca.acme.AcmeNonceData;
import org.ejbca.acme.AcmeOrderData;
import org.ejbca.core.ejb.approval.ApprovalData;
import org.ejbca.core.ejb.ca.publisher.PublisherData;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueData;
import org.ejbca.core.ejb.ca.store.CertReqHistoryData;
import org.ejbca.core.ejb.ca.validation.BlacklistData;
import org.ejbca.core.ejb.config.ClearCacheSessionLocal;
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceData;
import org.ejbca.core.ejb.services.ServiceData;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.peerconnector.PeerData;

import java.util.List;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class DatabaseSessionBean implements DatabaseSessionRemote {

    @PersistenceContext(unitName = CesecoreConfiguration.PERSISTENCE_UNIT)
    private EntityManager entityManager;

    <T> List<T> clearTable(Class<T> clazz, boolean deleteEntries) {
        final var list = entityManager.createQuery("select c from "+clazz.getSimpleName()+" c", clazz).getResultList();
        if (deleteEntries) {
            entityManager.createQuery("delete from "+clazz.getSimpleName()+" c").executeUpdate();
        }
        return list;
    }

    private ClearCacheSessionLocal clearCacheSessionLocal;

    private ClearCacheSessionLocal getClearCacheSessionLocal() {
        if (clearCacheSessionLocal == null) {
            clearCacheSessionLocal = new EjbLocalHelper()
                    .getClearCacheSession();
        }
        return clearCacheSessionLocal;
    }

    @Override
    public DatabaseContent clearTables(boolean clearProtectedTables) {
        var databaseContent = new DatabaseContent(
                clearTable(AccessRuleData.class, true),
                clearTable(AccessTreeUpdateData.class, true),
                clearTable(AccessUserAspectData.class, true),
                clearTable(AcmeAccountData.class, true),
                clearTable(AcmeAuthorizationData.class, true),
                clearTable(AcmeNonceData.class, true),
                clearTable(AcmeOrderData.class, true),
                clearTable(AdminGroupData.class, true),
                clearTable(AdminPreferencesData.class, true),
                clearTable(ApprovalData.class, true),
                clearTable(Base64CertData.class, true),
                clearTable(BlacklistData.class, true),
                clearTable(CAData.class, clearProtectedTables),
                clearTable(CertificateData.class, clearProtectedTables),
                clearTable(CertificateProfileData.class, true),
                clearTable(CertReqHistoryData.class, true),
                clearTable(CRLData.class, clearProtectedTables),
                clearTable(CryptoTokenData.class, clearProtectedTables),
                clearTable(EndEntityProfileData.class, true),
                clearTable(GlobalConfigurationData.class, clearProtectedTables),
                clearTable(IncompleteIssuanceJournalData.class, true),
                clearTable(InternalKeyBindingData.class, true),
                clearTable(KeyRecoveryData.class, true),
                clearTable(NoConflictCertificateData.class, true),
                clearTable(OcspResponseData.class, true),
                clearTable(PeerData.class, true),
                clearTable(ProfileData.class, true),
                clearTable(PublisherData.class, true),
                clearTable(PublisherQueueData.class, true),
                clearTable(RoleData.class, clearProtectedTables),
                clearTable(RoleMemberData.class, clearProtectedTables),
                clearTable(SctData.class, true),
                clearTable(ServiceData.class, true),
                clearTable(UserData.class, clearProtectedTables),
                clearTable(UserDataSourceData.class, true)
        );
        entityManager.flush();
        getClearCacheSessionLocal().clearCaches(false);
        return databaseContent;
    }

    @Override
    public void restoreTables(DatabaseContent databaseContent) {
        databaseContent.accessRuleData().forEach(entityManager::persist);
        databaseContent.accessTreeUpdateData().forEach(entityManager::persist);
        databaseContent.accessUserAspectData().forEach(entityManager::persist);
        databaseContent.acmeAccountData().forEach(entityManager::persist);
        databaseContent.acmeAuthorizationData().forEach(entityManager::persist);
        databaseContent.acmeNonceData().forEach(entityManager::persist);
        databaseContent.acmeOrderData().forEach(entityManager::persist);
        databaseContent.adminGroupData().forEach(entityManager::persist);
        databaseContent.adminPreferencesData().forEach(entityManager::persist);
        databaseContent.approvalData().forEach(entityManager::persist);
        databaseContent.base64CertData().forEach(entityManager::persist);
        databaseContent.blacklistData().forEach(entityManager::persist);
        databaseContent.caData().forEach(entityManager::persist);
        databaseContent.certificateData().forEach(entityManager::persist);
        databaseContent.certificateProfileData().forEach(entityManager::persist);
        databaseContent.certReqHistoryData().forEach(entityManager::persist);
        databaseContent.crlData().forEach(entityManager::persist);
        databaseContent.cryptoTokenData().forEach(entityManager::persist);
        databaseContent.endEntityProfileData().forEach(entityManager::persist);
        databaseContent.globalConfigurationData().forEach(entityManager::persist);
        databaseContent.incompleteIssuanceJournalData().forEach(entityManager::persist);
        databaseContent.internalKeyBindingData().forEach(entityManager::persist);
        databaseContent.keyRecoveryData().forEach(entityManager::persist);
        databaseContent.noConflictCertificateData().forEach(entityManager::persist);
        databaseContent.ocspResponseData().forEach(entityManager::persist);
        databaseContent.peerData().forEach(entityManager::persist);
        databaseContent.profileData().forEach(entityManager::persist);
        databaseContent.publisherData().forEach(entityManager::persist);
        databaseContent.publisherQueueData().forEach(entityManager::persist);
        databaseContent.roleData().forEach(entityManager::persist);
        databaseContent.roleMemberData().forEach(entityManager::persist);
        databaseContent.sctData().forEach(entityManager::persist);
        databaseContent.serviceData().forEach(entityManager::persist);
        databaseContent.userData().forEach(entityManager::persist);
        databaseContent.userDataSourceData().forEach(entityManager::persist);
        getClearCacheSessionLocal().clearCaches(false);
        entityManager.flush();
    }

}
