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
package org.ejbca.core.ejb.keyrecovery;

import java.security.cert.Certificate;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyPairWrapper;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;

/**
 * @version $Id$
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "KeyRecoveryProxySessionRemote")
@TransactionAttribute(TransactionAttributeType.REQUIRED)
public class KeyRecoveryProxySessionBean implements KeyRecoveryProxySessionRemote {

    @EJB
    private KeyRecoverySessionLocal keyRecoverySession;
    
    @Override
    public boolean authorizedToKeyRecover(AuthenticationToken admin, int profileid) {
        return keyRecoverySession.authorizedToKeyRecover(admin, profileid);
    }

    @Override
    public void checkIfApprovalRequired(AuthenticationToken admin, CertificateWrapper certificate, String username, int endEntityProfileId,
            boolean checkNewest) throws ApprovalException, WaitingForApprovalException, CADoesntExistsException {
        keyRecoverySession.checkIfApprovalRequired(admin, certificate, username, endEntityProfileId, checkNewest);
    }

    @Override
    public boolean addKeyRecoveryData(AuthenticationToken admin, CertificateWrapper certificate, String username, KeyPairWrapper keypair)
            throws AuthorizationDeniedException {
        return keyRecoverySession.addKeyRecoveryData(admin, certificate, username, keypair);
    }

    @Override
    public void removeKeyRecoveryData(AuthenticationToken admin, CertificateWrapper certificate) throws AuthorizationDeniedException {
        keyRecoverySession.removeKeyRecoveryData(admin, certificate);
    }

    @Override
    public void removeAllKeyRecoveryData(AuthenticationToken admin, String username) {
        keyRecoverySession.removeAllKeyRecoveryData(admin, username);
    }

    @Override
    public KeyRecoveryInformation recoverKeys(AuthenticationToken admin, String username, int endEntityProfileId) throws AuthorizationDeniedException {
        return keyRecoverySession.recoverKeys(admin, username, endEntityProfileId);
    }

    @Override
    public boolean markNewestAsRecoverable(AuthenticationToken admin, String username, int endEntityProfileId) throws AuthorizationDeniedException,
            ApprovalException, WaitingForApprovalException, CADoesntExistsException {
        return keyRecoverySession.markNewestAsRecoverable(admin, username, endEntityProfileId);
    }

    @Override
    public boolean markAsRecoverable(AuthenticationToken admin, Certificate certificate, int endEntityProfileId) throws AuthorizationDeniedException,
            WaitingForApprovalException, ApprovalException, CADoesntExistsException {
        return keyRecoverySession.markAsRecoverable(admin, certificate, endEntityProfileId);
    }

    @Override
    public void unmarkUser(AuthenticationToken admin, String username) {
        keyRecoverySession.unmarkUser(admin, username);
    }

    @Override
    public boolean isUserMarked(String username) {
        return keyRecoverySession.isUserMarked(username);
    }

    @Override
    public boolean existsKeys(CertificateWrapper certificate) {
        return keyRecoverySession.existsKeys(certificate);
    }

    @Override
    public boolean addKeyRecoveryDataInternal(AuthenticationToken admin, CertificateWrapper certificate, String username, KeyPairWrapper keypair,
            int cryptoTokenId, String keyAlias) {
        return keyRecoverySession.addKeyRecoveryDataInternal(admin, certificate, username, keypair, cryptoTokenId, keyAlias);
    }

    @Override
    public KeyRecoveryInformation recoverKeysInternal(AuthenticationToken admin, String username, int cryptoTokenId, String keyAlias) {
        return keyRecoverySession.recoverKeysInternal(admin, username, cryptoTokenId, keyAlias);
    }

    @Override
    public boolean markAsRecoverableInternal(AuthenticationToken admin, CertificateWrapper certificate, String username) {
        return keyRecoverySession.markAsRecoverableInternal(admin, certificate, username);
    }

}
