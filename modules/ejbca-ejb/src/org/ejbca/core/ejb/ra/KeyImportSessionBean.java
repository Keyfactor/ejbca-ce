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
import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAData;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionLocal;
import org.cesecore.keys.keyimport.KeyImportFailure;
import org.cesecore.keys.keyimport.KeyImportKeystoreData;
import org.cesecore.keys.keyimport.KeyImportRequestData;
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
    public List<KeyImportFailure> importKeys(final AuthenticationToken authenticationToken, final KeyImportRequestData keyImportRequestData)
            throws CADoesntExistsException, AuthorizationDeniedException, EjbcaException {
        String caDn = keyImportRequestData.getIssuerDn();
        CAData caData = caSession.findBySubjectDN(caDn);
        if (caData == null) {
            log.error("No CA found with Subject DN " + caDn);
            throw new CADoesntExistsException("CA does not exist: " + caDn);
        }
        CAInfo caInfo = caSession.getCAInfo(authenticationToken, caData.getCaId());
        String certificateProfileName = keyImportRequestData.getCertificateProfileName();
        int certificateProfileId = certificateProfileSession.getCertificateProfileId(certificateProfileName);
        String endEntityProfileName = keyImportRequestData.getEndEntityProfileName();
        int endEntityProfileId = endEntityProfileSession.getEndEntityProfileId(endEntityProfileName);
        List<KeyImportKeystoreData> keystores = keyImportRequestData.getKeystores();
        if (CollectionUtils.isEmpty(keystores)) {
            log.error("No keystores found for key import request: " + keyImportRequestData);
            throw new EjbcaException("No keystores found in the key import request");
        }
        List<KeyImportFailure> failures = new ArrayList<>();

        for (KeyImportKeystoreData keystore : keystores) {
            // Process the keystore and if it fails record the failure reason. Either way, continue with the next keystore without interrupting
            try {
                processKeystoreSession.processKeyStore(authenticationToken, keystore, caInfo, caData, certificateProfileId, endEntityProfileId);
            } catch (KeyImportException e) {
                failures.add(new KeyImportFailure(keystore.getUsername(), e.getMessage()));
            }
        }

        return failures;
    }
}
