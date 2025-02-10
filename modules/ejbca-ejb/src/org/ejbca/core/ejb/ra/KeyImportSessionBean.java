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
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.cesecore.keys.keyimport.KeyImportRequestData;
import org.cesecore.keys.keyimport.KeyImportResponseData;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionLocal;
import org.ejbca.core.model.keyimport.KeyImportException;

import java.util.ArrayList;
import java.util.List;

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
    public KeyImportResponseData importKeys(final AuthenticationToken authenticationToken, final KeyImportRequestData keyImportRequestData) {
        KeyImportResponseData response = new KeyImportResponseData();
        List<KeyImportFailure> failures = new ArrayList<>();
        try {
            String caDn = keyImportRequestData.getIssuerDn();
            CAData caData = caSession.findBySubjectDN(caDn);
            if (caData == null) {
                log.error("No CA found with Subject DN " + caDn);
                throw new EjbcaException("CA does not exist. CA DN: " + caDn);
            }
            CAInfo caInfo = caSession.getCAInfo(authenticationToken, caData.getCaId());
            if (caInfo == null || StringUtils.isEmpty(caInfo.getSubjectDN())) {
                throw new EjbcaException("CAInfo is empty, looks like CA does not exist. CA id: " + caData.getCaId());
            }
            String certificateProfileName = keyImportRequestData.getCertificateProfileName();
            int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
            if (certificateProfileId == 0) {
                log.error("Certificate profile does not exist: " + certificateProfileName);
                throw new EjbcaException("Certificate profile does not exist: " + certificateProfileName);
            }
            String endEntityProfileName = keyImportRequestData.getEndEntityProfileName();
            int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
            List<KeyImportKeystoreData> keystores = keyImportRequestData.getKeystores();
            if (CollectionUtils.isEmpty(keystores)) {
                log.error("No keystores found for key import request: " + keyImportRequestData);
                throw new EjbcaException("No keystores found in the key import request");
            }

            for (KeyImportKeystoreData keystore : keystores) {
                // Process the keystore and if it fails record the failure reason. Either way, continue with the next keystore without interrupting
                try {
                    processKeystoreSession.processKeyStore(authenticationToken, keystore, caInfo, caData, certificateProfileId, endEntityProfileId);
                } catch (KeyImportException e) {
                    failures.add(new KeyImportFailure(keystore.getUsername(), e.getMessage()));
                }
            }
        } catch (Exception e) {
            response.setGeneralErrorMessage(e.getMessage());
        }
        response.setFailures(failures);
        return response;
    }
}
