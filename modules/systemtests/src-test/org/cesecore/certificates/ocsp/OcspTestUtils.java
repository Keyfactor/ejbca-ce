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

import java.io.IOException;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CesecoreException;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.keybind.CertificateImportException;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingNameInUseException;
import org.cesecore.keybind.InternalKeyBindingNonceConflictException;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.token.KeyGenParams;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.Assert;

/**
 *
 */
public final class OcspTestUtils {

    private static final String FOO123_PASSWORD = "foo123";
    private static final String PROPERTY_ALIAS = OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD;
    public static final String OCSP_END_USER_NAME = "OcspSigningUser";
    private static final String CLIENTSSL_END_USER_NAME = "ClientSSLUser";
    private static final String CLIENTSSL_END_USER_DN = "CN=clientSSLUser";

    private OcspTestUtils() {
        throw new IllegalStateException("This is utility class, not possible to instantiate it!");
    }

    public static void deleteCa(AuthenticationToken authenticationToken, X509CA x509ca) throws AuthorizationDeniedException {
        if (x509ca != null) {
            deleteCa(authenticationToken, (X509CAInfo) x509ca.getCAInfo());
        }
    }
    
    public static void deleteCa(AuthenticationToken authenticationToken, X509CAInfo x509ca) throws AuthorizationDeniedException {
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
     * Creates an internal key binding. Removes it if it already exists, for example from previous aborted or failed test runs.
     * @param authenticationToken authentication token
     * @param cryptoTokenId crypto token id
     * @param type internal key binding typ, i.e. OcspKeyBinding.IMPLEMENTATION_ALIAS
     * @param testName test names
     * @param keyspec keyspec for new key binding crypto token, i. "RSA2048", "secp256r1"
     * @param signAlg  is the signature algorithm that this InternalKeyBinding will use for signatures (if applicable), i.e. AlgorithmConstants.SIGALG_SHA1_WITH_RSA
     * @return internalKeyBindingId
     * @throws AuthorizationDeniedException 
     * @throws InvalidAlgorithmParameterException 
     * @throws CryptoTokenOfflineException 
     * @throws InvalidKeyException 
     * @throws InternalKeyBindingNonceConflictException 
     * @throws InvalidAlgorithmException 
     * @throws InternalKeyBindingNameInUseException 
     */
    public static int createInternalKeyBinding(AuthenticationToken authenticationToken, int cryptoTokenId, String type, String testName,
            String keyspec, String signAlg)
            throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException, InvalidAlgorithmParameterException,
            InternalKeyBindingNameInUseException, InvalidAlgorithmException, InternalKeyBindingNonceConflictException {
        CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        removeInternalKeyBinding(authenticationToken, testName);
        // First create a new CryptoToken
        if (!cryptoTokenManagementSession.isAliasUsedInCryptoToken(cryptoTokenId, testName)) {
            cryptoTokenManagementSession.createKeyPair(authenticationToken, cryptoTokenId, testName, KeyGenParams.builder(keyspec).build());
        }
        // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
        final Map<String, Serializable> dataMap = new LinkedHashMap<>();
        dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
        return internalKeyBindingMgmtSession.createInternalKeyBinding(authenticationToken, type, testName, InternalKeyBindingStatus.ACTIVE, null,
                cryptoTokenId, testName, signAlg, dataMap, null);
    }

    public static void updateInternalKeyBindingProperty(AuthenticationToken authenticationToken, int internalKeyBindinId, String nonExistingGood,
            String nonExistingRevoked, String nonExistingUnauth) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

        // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
        InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindinId);
        internalKeyBinding.setProperty(OcspConfiguration.NON_EXISTING_IS_GOOD, nonExistingGood);
        internalKeyBinding.setProperty(OcspConfiguration.NON_EXISTING_IS_REVOKED, nonExistingRevoked);
        internalKeyBinding.setProperty(OcspConfiguration.NON_EXISTING_IS_UNAUTHORIZED, nonExistingUnauth);

        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, internalKeyBinding);
    }

    /** Adds signOnBehalfEntries to a previously created OCSP key binding 
     * @throws AuthorizationDeniedException 
     * @throws InternalKeyBindingNameInUseException */
    public static void addSignOnBehalfEntries(AuthenticationToken authenticationToken, int internalKeyBindinId,
            List<InternalKeyBindingTrustEntry> signOcspResponseOnBehalf) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        InternalKeyBinding keyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken, internalKeyBindinId);
        if (!keyBinding.getImplementationAlias().equalsIgnoreCase(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
            return;
        }
        keyBinding.setSignOcspResponseOnBehalf(signOcspResponseOnBehalf);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, keyBinding);
    }

    /** @return the certificate fingerprint if an update was made */
    public static String updateInternalKeyBindingCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId)
            throws AuthorizationDeniedException, CertificateImportException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        return internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(authenticationToken, internalKeyBindingId);
    }

    /** @return true if the status was modified */
    public static boolean setInternalKeyBindingStatus(AuthenticationToken authenticationToken, int internalKeyBindingId,
            InternalKeyBindingStatus newStatus) throws AuthorizationDeniedException {
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        boolean statusChanged = internalKeyBindingMgmtSession.setStatus(authenticationToken, internalKeyBindingId, newStatus);
        final InternalKeyBindingStatus currentStatus = internalKeyBindingMgmtSession
                .getInternalKeyBindingInfo(authenticationToken, internalKeyBindingId).getStatus();
        assertEquals("Unable to change status of InternalKeyBinding.", newStatus, currentStatus);
        return statusChanged;
    }

    /** Set the untilNextUpate for an OcspKeyBinding */
    public static long setOcspKeyBindingUntilNextUpdate(AuthenticationToken authenticationToken, final int ocspKeyBindingId,
            final long untilNextUpdate) throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Configure the OcspKeyBinding's untilNextUpdate
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                ocspKeyBindingId);
        final long oldValue = ocspKeyBinding.getUntilNextUpdate();
        ocspKeyBinding.setUntilNextUpdate(untilNextUpdate);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        return oldValue;
    }

    public static long setOcspKeyBindingMaxAge(AuthenticationToken authenticationToken, int ocspKeyBindingId, long maxAge)
            throws AuthorizationDeniedException, InternalKeyBindingNameInUseException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Configure the OcspKeyBinding's untilNextUpdate
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                ocspKeyBindingId);
        final long oldValue = ocspKeyBinding.getMaxAge();
        ocspKeyBinding.setMaxAge(maxAge);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
        return oldValue;
    }

    public static void enableArchiveCutoff(final AuthenticationToken authenticationToken, final int ocspKeyBindingId,
            final SimpleTime retentionPeriod, final boolean useIssuerNotBeforeAsArchiveCutoff)
            throws InternalKeyBindingNameInUseException, AuthorizationDeniedException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                ocspKeyBindingId);
        final List<String> ocspExtensions = ocspKeyBinding.getOcspExtensions();
        if (!ocspExtensions.contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
            ocspExtensions.add(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId());
        }
        ocspKeyBinding.setOcspExtensions(ocspExtensions);
        ocspKeyBinding.setUseIssuerNotBeforeAsArchiveCutoff(useIssuerNotBeforeAsArchiveCutoff);
        ocspKeyBinding.setRetentionPeriod(retentionPeriod);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
    }

    public static void disableOmitRevocationReasonUnespecified(final AuthenticationToken authenticationToken, final int ocspKeyBindingId)
            throws InternalKeyBindingNameInUseException, AuthorizationDeniedException {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBindingMgmtSession.getInternalKeyBinding(authenticationToken,
                ocspKeyBindingId);
        ocspKeyBinding.setOmitReasonCodeEnabled(false);
        internalKeyBindingMgmtSession.persistInternalKeyBinding(authenticationToken, ocspKeyBinding);
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
            int internalKeyBindingId, int caId, int certificateProfileId, Date expirationTime) throws AuthorizationDeniedException,
            CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException,
            CertificateExtensionException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException,
            CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);

        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(
                internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken, internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(username, signerDN, caId, null, null, EndEntityTypes.ENDUSER.toEndEntityType(), 1,
                certificateProfileId, EndEntityConstants.TOKEN_USERGEN, null);
        user.setPassword(FOO123_PASSWORD);
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword(), expirationTime);
        return (X509Certificate) (certificateCreateSession
                .createCertificate(authenticationToken, user, req, X509ResponseMessage.class, signSession.fetchCertGenParams()).getCertificate());
    }

    public static X509Certificate createClientSSLCertificate(AuthenticationToken authenticationToken, int internalKeyBindingId, int caId)
            throws AuthorizationDeniedException, CesecoreException, CertificateExtensionException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.getPublicKeyFromBytes(
                internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(authenticationToken, internalKeyBindingId));
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(CLIENTSSL_END_USER_NAME, CLIENTSSL_END_USER_DN, caId, null, null,
                EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN,
                null);
        user.setPassword(FOO123_PASSWORD);
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        return (X509Certificate) (certificateCreateSession
                .createCertificate(authenticationToken, user, req, X509ResponseMessage.class, new CertificateGenerationParams()).getCertificate());
    }

    public static X509Certificate createUserCertificate(AuthenticationToken authenticationToken, int caId, String userName, String userDn)
            throws InvalidAlgorithmParameterException, CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException,
            CertificateCreateException, CryptoTokenOfflineException, SignRequestSignatureException, IllegalNameException, CertificateRevokeException,
            CertificateSerialNumberException, IllegalValidityException, CAOfflineException, InvalidAlgorithmException, AuthorizationDeniedException,
            CertificateExtensionException {
        CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
        // Get the public key for the key pair currently used in the binding
        PublicKey publicKey = KeyTools.genKeys("2048", "RSA").getPublic();
        // Issue a certificate in EJBCA for the public key
        final EndEntityInformation user = new EndEntityInformation(userName, userDn, caId, null, null, EndEntityTypes.ENDUSER.toEndEntityType(), 1,
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityConstants.TOKEN_USERGEN, null);
        user.setPassword(FOO123_PASSWORD);
        RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());
        return (X509Certificate) (certificateCreateSession
                .createCertificate(authenticationToken, user, req, X509ResponseMessage.class, new CertificateGenerationParams()).getCertificate());
    }

    public static void revokeUserCertificate(AuthenticationToken authenticationToken, X509Certificate certificate)
            throws CertificateRevokeException, AuthorizationDeniedException {
        InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalCertificateStoreSessionRemote.class);

        internalCertificateStoreSession.setRevokeStatus(authenticationToken, certificate, new Date(), null, RevokedCertInfo.REVOCATION_REASON_SUPERSEDED);
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

    public static void clearOcspSigningCache() {
        try {
            final URL url = new URL("http://localhost:8080/ejbca/clearcache?command=clearcaches&excludeactivects=true");
            final HttpURLConnection con = (HttpURLConnection) url.openConnection();
            if (con.getResponseCode() != HttpURLConnection.HTTP_OK) {
                Assert.fail("Failed to clear caches using URL: http://localhost:8080/ejbca/clearcache?command=clearcaches&excludeactivects=true"
                        + ". The response code was: " + con.getResponseCode());
            }
        } catch (IOException e) {
            Assert.fail("Failed to clear caches using URL: http://localhost:8080/ejbca/clearcache?command=clearcaches&excludeactivects=true"
                    + ". The error was: " + e.getMessage());
        }
    }

    public static CAInfo createExternalCa(AuthenticationToken alwaysAllowtoken, KeyPair caKeyPair, String issuerDn, String caName, long validity)
            throws OperatorCreationException, CertificateException, CAExistsException, IllegalCryptoTokenException, CertificateImportException,
            AuthorizationDeniedException {
        final CAAdminSessionRemote caAdminSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class);
        final CaSessionRemote caSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        Certificate cert = CertTools.genSelfCert(issuerDn, validity, "1.1.1.1", caKeyPair.getPrivate(), caKeyPair.getPublic(), "SHA256WithRSA", true,
                "BC");
        List<Certificate> certs = new ArrayList<>();
        certs.add(cert);

        caAdminSessionRemote.importCACertificate(alwaysAllowtoken, caName, EJBTools.wrapCertCollection(certs));
        return caSessionRemote.getCAInfo(alwaysAllowtoken, caName);
    }

    public static Certificate createCertByExternalCa(final KeyPair caKeyPair, String userDn, long validity) throws InvalidAlgorithmParameterException, OperatorCreationException, CertificateException {

        KeyPair userKeyPair = KeyTools.genKeys("2048", "RSA");
        return CertTools.genSelfCert(userDn, validity, "1.1.1.1", caKeyPair.getPrivate(), userKeyPair.getPublic(), "SHA256WithRSA", false, "BC");
    }

}
