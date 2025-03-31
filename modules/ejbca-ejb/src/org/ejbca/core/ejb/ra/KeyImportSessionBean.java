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

package org.ejbca.core.ejb.ra;

import jakarta.ejb.EJB;
import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.configuration.GlobalConfigurationSessionLocal;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.cesecore.keys.keyimport.KeyImportRequestData;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.keyimport.KeyImportException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Implementation of KeyImportSession
 */

@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class KeyImportSessionBean implements KeyImportSessionLocal, KeyImportSessionRemote {
    
    private static final Logger log = Logger.getLogger(KeyImportSessionBean.class);

    @EJB
    private EndEntityProfileSessionLocal endEntityProfileSession;
    @EJB
    private CertificateProfileSessionLocal certificateProfileSession;
    @EJB
    private CaSessionLocal caSession;
    @EJB
    private ProcessKeystoreSessionLocal processKeystoreSession;

    @Override
    public List<KeyImportFailure> importKeys(final AuthenticationToken authenticationToken, final KeyImportRequestData keyImportRequestData) throws AuthorizationDeniedException, EjbcaException {
        List<KeyImportFailure> keyImportFailures = new ArrayList<>();

        final String caSubjectDN = keyImportRequestData.getIssuerDn();
        final ImmutablePair<CAData, CAInfo> caDataAndInfo = verifyCertificateAuthority(authenticationToken, caSubjectDN);

        final String certificateProfileName = keyImportRequestData.getCertificateProfileName();
        final ImmutablePair<Integer, CertificateProfile> certificateProfileIdAndData = verifyCertificateProfile(certificateProfileName);

        // Key migration is not supported when approvals are enabled in CA or CP.
        if (isApprovalsEnabled(certificateProfileIdAndData.getRight().getApprovals(), caDataAndInfo.getRight().getApprovals())) {
            throw new EjbcaException("Certificate profile or CA has approvals enabled for end entity operations. Cannot be used for key import.");
        }

        String endEntityProfileName = keyImportRequestData.getEndEntityProfileName();
        final ImmutablePair<Integer, EndEntityProfile> endEntityProfileIdAndData = verifyEndEntityProfile(endEntityProfileName);

        verifyAvailabilities(caDataAndInfo.getRight().getCAId(), certificateProfileIdAndData.getLeft(),
                             certificateProfileIdAndData.getRight(), endEntityProfileIdAndData.getRight());

        List<KeyImportKeystoreData> keystores = keyImportRequestData.getKeystores();
        if (CollectionUtils.isEmpty(keystores)) {
            throw new KeyImportException("No keystores found in the key import request");
        }

        for (KeyImportKeystoreData keystore : keystores) {
            // Process the keystore and if it fails record the failure reason. Either way, continue with the next keystore without interrupting
            try {
                processKeystoreSession.processKeyStore(authenticationToken, keystore,
                                                       caDataAndInfo.getRight(), caDataAndInfo.getLeft(),
                                                       certificateProfileIdAndData.getLeft(), endEntityProfileIdAndData.getLeft());
            } catch (KeyImportException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Key import has failed for username: " + keystore.getUsername() + " - " + e.getMessage());
                }
                keyImportFailures.add(new KeyImportFailure(keystore.getUsername(), e.getMessage()));
            }
        }

        return keyImportFailures;
    }

    /**
     * Verify that the request has valid Certificate Profile name and return relevant data.
     *
     * @param certificateProfileName        Certificate Profile name
     * @return                              Pair of: Profile Id and Profile Data
     *
     * @throws KeyImportException
     */
    private ImmutablePair<Integer, CertificateProfile> verifyCertificateProfile(final String certificateProfileName) throws KeyImportException {
        final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        if (certificateProfileId == 0) {
            throw new KeyImportException("Certificate profile does not exist: " + certificateProfileName);
        }

        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
        return ImmutablePair.of(certificateProfileId, certificateProfile);
    }

    /**
     * Verify that the request has valid End Entity Profile name and return relevant data.
     *
     * @param endEntityProfileName      EEP name
     * @return                          Pair of ID and EEP Data
     *
     * @throws KeyImportException
     */
    private ImmutablePair<Integer, EndEntityProfile> verifyEndEntityProfile(final String endEntityProfileName) throws KeyImportException {
        try {
            final int eepId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
            final EndEntityProfile eep = endEntityProfileSession.getEndEntityProfile(eepId);

            return ImmutablePair.of(eepId, eep);
        } catch (EndEntityProfileNotFoundException e) {
            throw new KeyImportException("End Entity Profile doesn't exist: " + endEntityProfileName);
        }
    }

    /**
     * Verify that the request has valid Certificate Authority name and return relevant data.
     *
     * @param authenticationToken       Auth token
     * @param caSubjectDn               CA subject DN
     * @return                          Pair of CAData and CAInfo
     *
     * @throws EjbcaException
     * @throws AuthorizationDeniedException
     */
    private ImmutablePair<CAData, CAInfo> verifyCertificateAuthority(final AuthenticationToken authenticationToken, final String caSubjectDn) throws EjbcaException, AuthorizationDeniedException {
        final CAData caData = caSession.findBySubjectDN(caSubjectDn);
        if (caData == null) {
            throw new KeyImportException("CA does not exist. CA DN: " + caSubjectDn);
        }

        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, caData.getCaId());
        if (caInfo == null || StringUtils.isEmpty(caInfo.getSubjectDN())) {
            if (log.isDebugEnabled()) {
                log.debug("CAInfo is empty, looks like CA does not exist. CA Id: " + caData.getCaId());
            }
            throw new KeyImportException("CA does not exist. CA DN: " + caSubjectDn);
        }

        if (caInfo.getStatus() == CAConstants.CA_OFFLINE ||
            caInfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
            throw new EjbcaException("CA is not active.");
        }

        if (caInfo.getCAType() != CAInfo.CATYPE_X509) {
            throw new EjbcaException("Key import is only available for X509 CAs.");
        }

        return ImmutablePair.of(caData, caInfo);
    }

    /**
     * Verify CA exists in available CAs in profiles, and CP is set as available in EEP
     *
     * @param caId                      CA Id
     * @param certificateProfileId      CP Id
     * @param certificateProfile        Certificate Profile
     * @param endEntityProfile          End Entity Profile
     *
     * @throws EjbcaException
     */
    private void verifyAvailabilities(final int caId, final int certificateProfileId, final CertificateProfile certificateProfile, final EndEntityProfile endEntityProfile) throws EjbcaException {
        // CP uses -1 for "Any CA" and EEP uses 1
        final boolean caExistsInCP = certificateProfile.getAvailableCAs().contains(caId) || certificateProfile.getAvailableCAs().contains(CertificateProfile.ANYCA);
        final boolean caExistsInEEP = endEntityProfile.getAvailableCAs().contains(caId) || endEntityProfile.getAvailableCAs().contains(CAConstants.ALLCAS);

        final boolean cpExistsInEEP = endEntityProfile.getAvailableCertificateProfileIds().contains(certificateProfileId);

        if (!(caExistsInCP && caExistsInEEP)) {
            throw new EjbcaException("CA is not selected as available in Certificate Profile or End Entity Profile");
        }

        if (!cpExistsInEEP) {
            throw new EjbcaException("Certificate Profile is not selected as available in the End Entity Profile");
        }
    }

    /**
     * Verify whether add/edit EE Approvals are set in CA or CP, since they are not supported with key import.
     *
     * @param certificateProfileApprovals       Approvals from Certificate Profile
     * @param certificateAuthorityApprovals     Approvals from Certificate Authority
     * @return
     */
    private boolean isApprovalsEnabled(final Map<ApprovalRequestType, Integer> certificateProfileApprovals, final Map<ApprovalRequestType, Integer> certificateAuthorityApprovals) {
        final Integer caEndEntityApprovals = certificateAuthorityApprovals.get(ApprovalRequestType.ADDEDITENDENTITY);
        final Integer cpEndEntityApprovals = certificateProfileApprovals.get(ApprovalRequestType.ADDEDITENDENTITY);


        return (cpEndEntityApprovals != null && cpEndEntityApprovals != ApprovalProfile.NO_PROFILE_ID) ||
               (caEndEntityApprovals != null && caEndEntityApprovals != ApprovalProfile.NO_PROFILE_ID);
    }
}
