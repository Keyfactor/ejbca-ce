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

import java.math.BigInteger;
import java.util.Date;
import java.util.List;
import java.util.Set;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.configuration.ConfigurationBase;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.protocol.acme.AcmeAccount;
import org.ejbca.core.protocol.acme.AcmeAuthorization;
import org.ejbca.core.protocol.acme.AcmeChallenge;
import org.ejbca.core.protocol.acme.AcmeOrder;
import org.ejbca.core.protocol.acme.AcmeRaMasterApiSessionLocal;

/**
 * Proxy for identifying all calls that are needed in the RaMasterApi to fully support ACME.
 * 
 * Not available in Community Edition
 *
 */
@Stateless
// We can't rely on transactions for calls that will do persistence over the RaMasterApi, so avoid the overhead of when methods are invoked
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class AcmeRaMasterApiSessionBean implements AcmeRaMasterApiSessionLocal {
    
    @Override
    public void revokeCert(AuthenticationToken authenticationToken, BigInteger certserno, Date revocationdate, String issuerdn, int reason,
            boolean checkDate) throws AuthorizationDeniedException, NoSuchEndEntityException, ApprovalException, WaitingForApprovalException,
            RevokeBackDateNotAllowedForProfileException, AlreadyRevokedException, CADoesntExistsException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public CertificateDataWrapper searchForCertificate(final AuthenticationToken authenticationToken, final String fingerprint) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<CertificateWrapper> searchForCertificateChain(AuthenticationToken authenticationToken, String fingerprint) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeAccount getAcmeAccount(final String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeAccount getAcmeAccountByPublicKeyStorageId(final String publicKeyStorageId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String persistAcmeAccountData(final AcmeAccount acmeAccount) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeOrder getAcmeOrder(final String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public Set<AcmeOrder> getAcmeOrdersByAccountId(final String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public Set<AcmeOrder> getFinalizedAcmeOrdersByFingerprint(final String fingerprint) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public String persistAcmeOrderData(final AcmeOrder acmeOrder) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<String> persistAcmeOrderData(final List <AcmeOrder> acmeOrders) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public void removeAcmeOrder(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");    
    }

    @Override
    public void removeAcmeOrders(List<String> orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeAuthorization getAcmeAuthorizationById(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByOrderId(String orderId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeAuthorization> getAcmeAuthorizationsByAccountId(String accountId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public String persistAcmeAuthorizationData(AcmeAuthorization acmeAuthorization) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void persistAcmeAuthorizationDataList(List<AcmeAuthorization> acmeAuthorizations) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public AcmeChallenge getAcmeChallengeById(String challengeId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public List<AcmeChallenge> getAcmeChallengesByAuthorizationId(String authorizationId) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void persistAcmeChallengeData(AcmeChallenge acmeChallenge) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public void persistAcmeChallengeDataList(List<AcmeChallenge> acmeChallenges) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public boolean useAcmeReplayNonce(final String nonce, final long timeCreated, final long timeExpires) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(final AuthenticationToken authenticationToken, final String endEntityAccessRule) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(final AuthenticationToken authenticationToken) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public IdNameHashMap<CAInfo> getAuthorizedCAInfos(final AuthenticationToken authenticationToken) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public EndEntityInformation searchUser(final AuthenticationToken authenticationToken, final String username) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
    
    @Override
    public void addUser(final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public byte[] createCertificate(final AuthenticationToken authenticationToken, final EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public Set<String> getCaaIdentities(final AuthenticationToken authenticationToken, final int caId)
            throws CADoesntExistsException, AuthorizationDeniedException {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public <T extends ConfigurationBase> T getGlobalConfiguration(final Class<T> type) {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }

    @Override
    public boolean isPeerAuthorizedAcme() {
        throw new UnsupportedOperationException("ACME calls are only supported in EJBCA Enterprise");
    }
}
