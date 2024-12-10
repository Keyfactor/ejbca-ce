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
import org.ejbca.core.ejb.keyrecovery.KeyRecoveryData;
import org.ejbca.core.ejb.ra.UserData;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferencesData;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileData;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceData;
import org.ejbca.core.ejb.services.ServiceData;
import org.ejbca.peerconnector.PeerData;

import java.io.Serializable;
import java.util.List;

public record DatabaseContent(
        List<AccessRuleData> accessRuleData,
        List<AccessTreeUpdateData> accessTreeUpdateData,
        List<AccessUserAspectData> accessUserAspectData,
        List<AcmeAccountData> acmeAccountData,
        List<AcmeAuthorizationData> acmeAuthorizationData,
        List<AcmeNonceData> acmeNonceData,
        List<AcmeOrderData> acmeOrderData,
        List<AdminGroupData> adminGroupData,
        List<AdminPreferencesData> adminPreferencesData,
        List<ApprovalData> approvalData,
        List<Base64CertData> base64CertData,
        List<BlacklistData> blacklistData,
        List<CAData> caData,
        List<CertificateData> certificateData,
        List<CertificateProfileData> certificateProfileData,
        List<CertReqHistoryData> certReqHistoryData,
        List<CRLData> crlData,
        List<CryptoTokenData> cryptoTokenData,
        List<EndEntityProfileData> endEntityProfileData,
        List<GlobalConfigurationData> globalConfigurationData,
        List<IncompleteIssuanceJournalData> incompleteIssuanceJournalData,
        List<InternalKeyBindingData> internalKeyBindingData,
        List<KeyRecoveryData> keyRecoveryData,
        List<NoConflictCertificateData> noConflictCertificateData,
        List<OcspResponseData> ocspResponseData,
        List<PeerData> peerData,
        List<ProfileData> profileData,
        List<PublisherData> publisherData,
        List<PublisherQueueData> publisherQueueData,
        List<RoleData> roleData,
        List<RoleMemberData> roleMemberData,
        List<SctData> sctData,
        List<ServiceData> serviceData,
        List<UserData> userData,
        List<UserDataSourceData> userDataSourceData) implements Serializable {
}
