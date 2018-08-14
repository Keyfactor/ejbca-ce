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

package org.ejbca.core.protocol.acme;

import java.util.LinkedHashMap;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.era.IdNameHashMap;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
/**
 * Proxy for identifying all calls that are needed in the RaMasterApi to fully support ACME.
 *
 *
 * @version $Id$
 */
@Local
public interface AcmeRaMasterApiSessionLocal {

    /** @see org.ejbca.core.model.era.RaMasterApi#changeCertificateStatus(AuthenticationToken, String, int, int) */
    boolean changeCertificateStatus(AuthenticationToken authenticationToken, String fingerprint, int newStatus, int revocationReason)
            throws ApprovalException, WaitingForApprovalException;

    /** @see org.ejbca.core.model.era.RaMasterApi#searchForCertificate(AuthenticationToken, String) */
    CertificateDataWrapper searchForCertificate(AuthenticationToken authenticationToken, String fingerprint);

    /** @see org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#getAccountById(String) */
    AcmeAccount getAcmeAccount(String accountId);

    /** @see org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#getAccountById(String) */
    AcmeAccount getAcmeAccountByPublicKeyStorageId(String publicKeyStorageId);

    /** @see org.ejbca.core.protocol.acme.AcmeAccountDataSessionBean#persist(String, String, LinkedHashMap) */
    String persistAcmeAccountData(AcmeAccount acmeAccount);

    /** @see org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#getAcmeOrderById(String) */
    AcmeOrder getAcmeOrder(String orderId);

    /** @see org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#getAcmeOrdersByAccountId(String) */
    Set<AcmeOrder> getAcmeOrdersByAccountId(String accountId);

    /** @see org.ejbca.ui.web.protocol.acme.storage.AcmeOrderDataSessionBean#persist(String, String, LinkedHashMap) */
    String persistAcmeOrderData(AcmeOrder acmeOrder);

    /** @see  org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#getAcmeAuthorization(String) */
    AcmeAuthorization getAcmeAuthorizationById(String authorizationId);

    /** @see org.ejbca.core.protocol.acme.AcmeAuthorizationDataSessionBean#createOrUpdate(AcmeAuthorization) */
    String persistAcmeAuthorizationData(AcmeAuthorization acmeAuthorization);

    /** @see org.ejbca.core.protocol.acme.AcmeNonceDataSessionBean#useNonce(String, long, long) */
    boolean useAcmeReplayNonce(String nonce, long timeCreated, long timeExpires);

    /** @see org.ejbca.core.model.era.RaMasterApi#getAuthorizedEndEntityProfiles(AuthenticationToken, String) */
    IdNameHashMap<EndEntityProfile> getAuthorizedEndEntityProfiles(AuthenticationToken authenticationToken, String endEntityAccessRule);

    /** @see org.ejbca.core.model.era.RaMasterApi#getAuthorizedCertificateProfiles(AuthenticationToken) */
    IdNameHashMap<CertificateProfile> getAuthorizedCertificateProfiles(AuthenticationToken authenticationToken);

    /** @see org.ejbca.core.model.era.RaMasterApi#getAuthorizedCAInfos(AuthenticationToken) */
    IdNameHashMap<CAInfo> getAuthorizedCAInfos(AuthenticationToken authenticationToken);

    /** @see org.ejbca.core.model.era.RaMasterApi#addUser(AuthenticationToken, EndEntityInformation, boolean) */
    void addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException;

    /** @see org.ejbca.core.model.era.RaMasterApi#createCertificate(AuthenticationToken, EndEntityInformation) */
    byte[] createCertificate(AuthenticationToken authenticationToken, EndEntityInformation endEntityInformation)
            throws AuthorizationDeniedException, EjbcaException;

    /** @see org.ejbca.core.model.era.RaMasterApi#getCaaIdentities(AuthenticationToken, int) */
    Set<String> getCaaIdentities(AuthenticationToken authenticationToken, int caId) throws CADoesntExistsException, AuthorizationDeniedException;

    boolean isPeerAuthorizedAcme();

}