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
package org.cesecore.certificates.ocsp;

import static org.junit.Assert.assertEquals;

import java.io.Serializable;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;

/**
 * @version $Id$
 *
 */
public class OcspTestUtils {

    private static final String PROPERTY_ALIAS = OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD;
    public static final String OCSP_END_USER_NAME = "OcspSigningUser";
    private static final String CLIENTSSL_END_USER_NAME = "ClientSSLUser";
    private static final String CLIENTSSL_END_USER_DN = "CN=clientSSLUser";

    public static void deleteCa(AuthenticationToken authenticationToken, X509CA x509ca) throws AuthorizationDeniedException {
        if (x509ca != null) {
            CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
            CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                    .getRemoteSession(CryptoTokenManagementSessionRemote.class);
            int caCryptoTokenId = caSession.getCAInfo(authenticationToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(authenticationToken, caCryptoTokenId);
            caSession.removeCA(authenticationToken, x509ca.getCAId());
        }
    }

    /**
     * 
     * @param authenticationToken
     * @param cryptoTokenId
     * @param type internal key binding typ, i.e. OcspKeyBinding.IMPLEMENTATION_ALIAS
     * @param testName 
     * @param keyspec keyspec for new key binding crypto token, i. "RSA2048", "secp256r1"
     * @param signAlg  is the signature algorithm that this InternalKeyBinding will use for signatures (if applicable), i.e. AlgorithmConstants.SIGALG_SHA1_WITH_RSA
     * @return internalKeyBindingId
     * @throws InvalidKeyException
     * @throws CryptoTokenOfflineException
     * @throws InvalidAlgorithmParameterException
     * @throws AuthorizationDeniedException
     * @throws InternalKeyBindingNameInUseException
     * @throws InvalidAlgorithmException
     */
    public static int createInternalKeyBinding(AuthenticationToken authenticationToken, int cryptoTokenId, String type, String testName, String keyspec, String sigAlg) throws InvalidKeyException,
            CryptoTokenOfflineException, InvalidAlgorithmParameterException, AuthorizationDeniedException, InternalKeyBindingNameInUseException, InvalidAlgorithmException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // First create a new CryptoToken
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, testName)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, testName, keyspec);
        }
        // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
        final Map<String, Serializable> dataMap = new LinkedHashMap<String, Serializable>();
        dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
        int internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, type,
                testName, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, testName, sigAlg, dataMap, null);
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

    /** Set the untilNextUpate for an OcspKeyBinding */
    public static long setOcspKeyBindingUntilNextUpdate(AuthenticationToken authenticationToken, final int ocspKeyBindingId, final long untilNextUpdate)
            throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Configure the OcspKeyBinding's untilNextUpdate
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, ocspKeyBindingId);
        final long oldValue = ocspKeyBinding.getUntilNextUpdate();
        ocspKeyBinding.setUntilNextUpdate(untilNextUpdate);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        return oldValue;
    }

    public static long setOcspKeyBindingMaxAge(AuthenticationToken authenticationToken, int ocspKeyBindingId, long maxAge)
            throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Configure the OcspKeyBinding's untilNextUpdate
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, ocspKeyBindingId);
        final long oldValue = ocspKeyBinding.getMaxAge();
        ocspKeyBinding.setMaxAge(maxAge);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        return oldValue;
    }

    public static X509Certificate createOcspSigningCertificate(AuthenticationToken authenticationToken, String username, String signerDN,
            int internalKeyBindingId, int caId) throws CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException,
            CertificateCreateException, AuthorizationDeniedException, CertificateExtensionException, CryptoTokenOfflineException,
            SignRequestSignatureException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        return createOcspSigningCertificate(authenticationToken, username, signerDN, internalKeyBindingId, caId,
                CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER);
    }
    
    public static X509Certificate createOcspSigningCertificate(AuthenticationToken authenticationToken, String username, String signerDN,
            int internalKeyBindingId, int caId, int certificateProfileId) throws AuthorizationDeniedException, CustomCertificateSerialNumberException,
            IllegalKeyException, CADoesntExistsException, CertificateCreateException, CertificateExtensionException, CryptoTokenOfflineException,
            SignRequestSignatureException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        return createOcspSigningCertificate(authenticationToken, username, signerDN, internalKeyBindingId, caId, certificateProfileId, null);
        
    }
    
    public static X509Certificate createOcspSigningCertificate(AuthenticationToken authenticationToken, String username, String signerDN,
            int internalKeyBindingId, int caId, int certificateProfileId, Date expirationTime) throws AuthorizationDeniedException, CustomCertificateSerialNumberException,
            IllegalKeyException, CADoesntExistsException, CertificateCreateException, CertificateExtensionException, CryptoTokenOfflineException,
            SignRequestSignatureException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException,
            IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken,
                internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(username, signerDN, caId, null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 1, certificateProfileId,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword(), expirationTime);
        X509Certificate ocspSigningCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(
                authenticationToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
        return ocspSigningCertificate;
    }

    public static X509Certificate createClientSSLCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, int caId)
            throws AuthorizationDeniedException, CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException,
            CertificateCreateException, CesecoreException, CertificateExtensionException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken,
                internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(CLIENTSSL_END_USER_NAME, CLIENTSSL_END_USER_DN, caId, null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER,
                EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        X509Certificate ocspSigningCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(
                authenticationToken, user, req, X509ResponseMessage.class, new CertificateGenerationParams())).getCertificate());
        return ocspSigningCertificate;
    }

    public static void removeInternalKeyBinding(AuthenticationToken alwaysAllowtoken, String keyBindingName) throws AuthorizationDeniedException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        while (true) {
            final Integer keyBindingId = internalKeyBindingMgmtSession.getIdFromName(keyBindingName);
            if (keyBindingId == null) {
                return;
            }
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowtoken, keyBindingId);
        }
    }
}
