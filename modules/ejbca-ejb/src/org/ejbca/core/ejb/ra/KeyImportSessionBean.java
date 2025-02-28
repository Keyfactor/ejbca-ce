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
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.ca.ApprovalRequestType;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileDoesNotExistException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.cesecore.keys.keyimport.KeyImportRequestData;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.approval.profile.ApprovalProfile;
import org.ejbca.core.model.keyimport.KeyImportException;
import org.ejbca.core.model.ra.NotFoundException;

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
    public List<KeyImportFailure> importKeys(final AuthenticationToken authenticationToken, final KeyImportRequestData keyImportRequestData) throws CADoesntExistsException, AuthorizationDeniedException, CertificateProfileDoesNotExistException, EjbcaException {
        List<KeyImportFailure> keyImportFailures = new ArrayList<>();

        final String caDn = keyImportRequestData.getIssuerDn();
        final CAData caData = caSession.findBySubjectDN(caDn);
        final CAInfo caInfo = verifyCertificateAuthority(authenticationToken, caData, caDn);

        final String certificateProfileName = keyImportRequestData.getCertificateProfileName();
        final int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        if (certificateProfileId == 0) {
            final String certificateProfileErrorMessage = "Certificate profile does not exist: " + certificateProfileName;

            log.error(certificateProfileErrorMessage);
            throw new CertificateProfileDoesNotExistException(certificateProfileErrorMessage);
        }

        // Key migration is not supported when approvals are enabled.
        final CertificateProfile certificateProfile = certificateProfileSession.getCertificateProfile(certificateProfileId);
        if (isApprovalsEnabled(certificateProfile.getApprovals())) {
            final String approvalsErrorMessage = "Certificate profile '" + certificateProfileName + "' has approvals enabled for end entity operation and/or key recovery. Cannot be used for key import.";

            log.error(approvalsErrorMessage);
            throw new EjbcaException(approvalsErrorMessage);
        }

        String endEntityProfileName = keyImportRequestData.getEndEntityProfileName();
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);

        List<KeyImportKeystoreData> keystores = keyImportRequestData.getKeystores();
        if (CollectionUtils.isEmpty(keystores)) {
            log.error("No keystores found for key import request: " + keyImportRequestData);
            throw new NotFoundException("No keystores found in the key import request");
        }

        for (KeyImportKeystoreData keystore : keystores) {
            // Process the keystore and if it fails record the failure reason. Either way, continue with the next keystore without interrupting
            try {
                processKeystoreSession.processKeyStore(authenticationToken, keystore, caInfo, caData, certificateProfileId, endEntityProfileId);
            } catch (KeyImportException e) {
                keyImportFailures.add(new KeyImportFailure(keystore.getUsername(), e.getMessage()));
            }
        }

        return keyImportFailures;
    }

    private CAInfo verifyCertificateAuthority(AuthenticationToken authenticationToken, CAData caData, String caDn) throws CADoesntExistsException, EjbcaException, AuthorizationDeniedException {
        if (caData == null) {
            final String caErrorMessage = "CA does not exist. CA DN: " + caDn;

            log.error(caErrorMessage);
            throw new CADoesntExistsException(caErrorMessage);
        }

        final CAInfo caInfo = caSession.getCAInfo(authenticationToken, caData.getCaId());

        if (caInfo == null || StringUtils.isEmpty(caInfo.getSubjectDN())) {
            throw new CADoesntExistsException("CAInfo is empty, looks like CA does not exist. CA id: " + caData.getCaId());
        }

        if (caInfo.getStatus() == CAConstants.CA_OFFLINE ||
            caInfo.getStatus() == CAConstants.CA_UNINITIALIZED) {
            throw new EjbcaException("CA is not active");
        }

        if (caInfo.getCAType() != CAInfo.CATYPE_X509) {
            throw new EjbcaException("Key import is only available for X509 CAs.");
        }

        return caInfo;
    }

    private boolean isApprovalsEnabled( Map<ApprovalRequestType, Integer> approvals) {
        final Integer approvalForAddingEE = approvals.get(ApprovalRequestType.ADDEDITENDENTITY);
        final Integer approvalForKeyRecovery = approvals.get(ApprovalRequestType.KEYRECOVER);

        return (approvalForAddingEE != null && approvalForAddingEE != ApprovalProfile.NO_PROFILE_ID) ||
               (approvalForKeyRecovery != null && approvalForKeyRecovery != ApprovalProfile.NO_PROFILE_ID);
    }
}
