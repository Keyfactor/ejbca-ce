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
package org.cesecore.keybinding;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionLocal;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;

import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "TestInternalKeyBindingMgmtSessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class TestInternalKeyBindingMgmtSessionBean implements TestInternalKeyBindingMgmtSessionRemote {
    
    @EJB
    private InternalKeyBindingMgmtSessionLocal internalKeyBindingMgmtSession;

    @Override
    public void issueCertificateForInternalKeyBinding(AuthenticationToken authenticationToken, int internalKeyBindingId,
            EndEntityInformation endEntityInformation, String keySpec)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, 
            CertificateImportException, CertificateCreateException {
        internalKeyBindingMgmtSession.issueCertificateForInternalKeyBinding(
                authenticationToken, internalKeyBindingId, endEntityInformation, keySpec);
    }

    @Override
    public int createInternalKeyBindingWithOptionalEnrollmentInfo(AuthenticationToken authenticationToken, String type, int id, String name,
            InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, boolean allowMissingKeyPair,
            String signatureAlgorithm, Map<String, Serializable> dataMap, List<InternalKeyBindingTrustEntry> trustedCertificateReferences,
            String subjectDn, String issuerDn, String certificateProfileName, String endEntityProfileName, String keySpec)
            throws AuthorizationDeniedException, CryptoTokenOfflineException, InternalKeyBindingNameInUseException, InvalidAlgorithmException,
            InternalKeyBindingNonceConflictException {
        return internalKeyBindingMgmtSession.createInternalKeyBindingWithOptionalEnrollmentInfo(
                authenticationToken, type, id, name, status, certificateId, cryptoTokenId, keyPairAlias, 
                allowMissingKeyPair, signatureAlgorithm, dataMap, trustedCertificateReferences, subjectDn, 
                issuerDn, certificateProfileName, endEntityProfileName, keySpec);
    }
    

}
