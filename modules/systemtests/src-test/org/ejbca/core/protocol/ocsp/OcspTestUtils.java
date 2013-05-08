/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.core.protocol.ocsp;

import static org.junit.Assert.assertEquals;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.ejb.RemoveException;
import javax.persistence.PersistenceException;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CustomCertSerialNumberException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.keybind.CertificateImportException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.keybind.InternalKeyBindingNameInUseException;
import org.ejbca.core.ejb.keybind.InternalKeyBindingStatus;
import org.ejbca.core.ejb.keybind.impl.OcspKeyBinding;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;

/**
 * @version $Id$
 *
 */
public class OcspTestUtils {

    private static final String PROPERTY_ALIAS = OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD;
    private static final String SIGNER_DN = "CN=ocspTestSigner";
    private static final String OCSP_END_USER_NAME = "OcspSigningUser";
    private static final String CLIENTSSL_END_USER_NAME = "ClientSSLUser";
    private static final String CLIENTSSL_END_USER_DN = "CN=clientSSLUser";

    public static void deleteCa(AuthenticationToken authenticationToken, X509CA x509ca) throws AuthorizationDeniedException {
        if (x509ca != null) {
            CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            int caCryptoTokenId;
            try {
                caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
                cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
                caSession.removeCA(authenticationToken, x509ca.getCAId());
            } catch (CADoesntExistsException e) {
                //CA doesn't exist, ignore.
            }

        }
    }

    public static int createInternalKeyBinding(AuthenticationToken authenticationToken, int cryptoTokenId, String type, String testName) throws InvalidKeyException,
            CryptoTokenOfflineException, InvalidAlgorithmParameterException, AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // First create a new CryptoToken
        cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, testName, "RSA2048");
        // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
        final Map<Object, Object> dataMap = new LinkedHashMap<Object, Object>();
        dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
        int internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, type,
                testName, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, testName, dataMap);
        return internalKeyBindingId;
    }
    
    /** @return the certificate fingerprint if an update was made */
    public static String updateInternalKeyBindingCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CertificateImportException, CryptoTokenOfflineException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        return internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
    }

    /** @return true if the status was modified */
    public static boolean setInternalKeyBindingStatus(AuthenticationToken authenticationToken, int internalKeyBindingId, InternalKeyBindingStatus newStatus)
            throws AuthorizationDeniedException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        boolean statusChanged = internalKeyBindingMgmtSession.setStatus(authenticationToken, internalKeyBindingId, newStatus);
        final InternalKeyBindingStatus currentStatus = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(authenticationToken, internalKeyBindingId).getStatus();
        assertEquals("Unable to change status of InternalKeyBinding.", newStatus, currentStatus);
        return statusChanged;
    }

    public static X509Certificate createOcspSigningCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, int caId)
            throws AuthorizationDeniedException, CustomCertSerialNumberException, IllegalKeyException, CADoesntExistsException,
            CertificateCreateException, CesecoreException, RemoveException, PersistenceException, UserDoesntFullfillEndEntityProfile,
            WaitingForApprovalException, EjbcaException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken,
                internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(OCSP_END_USER_NAME, SIGNER_DN, caId, null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        try {
            endEntityManagementSession.deleteUser(authenticationToken, OCSP_END_USER_NAME);
        } catch (NotFoundException e) {
            //Ignore
        }
        endEntityManagementSession.addUser(authenticationToken, user, true);
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        X509Certificate ocspSigningCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(
                authenticationToken, user, req, X509ResponseMessage.class)).getCertificate());
        return ocspSigningCertificate;
    }

    public static X509Certificate createClientSSLCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, int caId)
            throws AuthorizationDeniedException, CustomCertSerialNumberException, IllegalKeyException, CADoesntExistsException,
            CertificateCreateException, CesecoreException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken,
                internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(CLIENTSSL_END_USER_NAME, CLIENTSSL_END_USER_DN, caId, null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        X509Certificate ocspSigningCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(
                authenticationToken, user, req, X509ResponseMessage.class)).getCertificate());
        return ocspSigningCertificate;
    }
}
