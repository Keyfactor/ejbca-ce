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
package org.cesecore.keybind;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.junit.util.CryptoTokenRule;
import org.cesecore.junit.util.CryptoTokenTestRunner;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.TraceLogMethodsRule;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;
import org.junit.runner.RunWith;

/**
 * @see InternalKeyBindingMgmtSession
 * @version $Id$
 */
@RunWith(CryptoTokenTestRunner.class)
public class InternalKeyBindingMgmtTest {

    private static final Logger log = Logger.getLogger(InternalKeyBindingMgmtTest.class);
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(InternalKeyBindingMgmtTest.class.getSimpleName()));
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private static final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private static final SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    
    private static final InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final String TESTCLASSNAME = InternalKeyBindingMgmtTest.class.getSimpleName();
    private static final String KEYBINDING_TYPE_ALIAS = OcspKeyBinding.IMPLEMENTATION_ALIAS;
    private static final String PROPERTY_ALIAS = OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @ClassRule
    public static CryptoTokenRule cryptoTokenRule = new CryptoTokenRule();
    
    private static X509CA x509ca;
    private static int cryptoTokenId;
    
    @BeforeClass
    public static void beforeClass() throws Throwable {
        x509ca = cryptoTokenRule.createX509Ca();
        cryptoTokenId = x509ca.getCAToken().getCryptoTokenId();
    }
    
    @AfterClass
    public static void afterClass() {
        cryptoTokenRule.cleanUp();
    }
   
        
    @Test
    public void assertTestPreRequisites() throws Exception {
        // Request all available implementations from server and verify that the implementation we intend to use exists
        final Map<String, Map<String, InternalKeyBindingProperty<? extends Serializable>>> availableTypesAndProperties = internalKeyBindingMgmtSession
                .getAvailableTypesAndProperties();
        final Map<String, InternalKeyBindingProperty<? extends Serializable>> availableProperties = availableTypesAndProperties
                .get(KEYBINDING_TYPE_ALIAS);
        assertNotNull("Expected " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.", availableProperties);
        // Verify that a property we intend to modify exists for our key binding implementation
        assertTrue("Expected property " + PROPERTY_ALIAS + " in " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.",
                availableProperties.containsKey(PROPERTY_ALIAS));
    }

    @Test
    public void activationNotPossibleWithoutCertificateReference() throws Exception {
        final String TEST_METHOD_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String KEY_BINDING_NAME = TEST_METHOD_NAME;
        final String KEY_PAIR_ALIAS = TEST_METHOD_NAME;
        removeInternalKeyBindingByName(alwaysAllowToken, TEST_METHOD_NAME);
        int internalKeyBindingId = 0;
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
            final Map<String, Serializable> dataMap = new LinkedHashMap<String, Serializable>();
            dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
            // Check that the status is not ACTIVE, despite our request (since no certificate reference was provided)
            final InternalKeyBinding internalKeyBinding = internalKeyBindingMgmtSession.getInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            assertEquals("Creation of active IKB with without a certificate reference was allowed.", InternalKeyBindingStatus.DISABLED.name(),
                       internalKeyBinding.getStatus().name());
            internalKeyBinding.setStatus(InternalKeyBindingStatus.ACTIVE);
            internalKeyBindingMgmtSession.persistInternalKeyBinding(alwaysAllowToken, internalKeyBinding);
            final InternalKeyBinding internalKeyBindingUpdated = internalKeyBindingMgmtSession.getInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            assertEquals("Update of active IKB with without a certificate reference was allowed.", InternalKeyBindingStatus.DISABLED.name(),
                    internalKeyBindingUpdated.getStatus().name());
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
        }
        
    }

    @Test
    public void workflowIssueCertFromPublicKeyAndUpdate() throws Exception {
        final String TEST_METHOD_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String KEY_BINDING_NAME = TEST_METHOD_NAME;
        final String KEY_BINDING_NAME1 = TEST_METHOD_NAME+"1";
        final String KEY_BINDING_NAME2 = TEST_METHOD_NAME+"2";
        final String KEY_PAIR_ALIAS = TEST_METHOD_NAME;
        // Clean up old key binding
        removeInternalKeyBindingByName(alwaysAllowToken, TEST_METHOD_NAME);
        int internalKeyBindingId = 0;
        int internalKeyBindingId1 = 0;
        int internalKeyBindingId2 = 0;
        String certFpToDelete = null;
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
            final Map<String, Serializable> dataMap = new LinkedHashMap<String, Serializable>();
            dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
            // Get the public key for the key pair currently used in the binding
            PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId));
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setPassword("foo123");
            RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());            
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
            certFpToDelete = CertTools.getFingerprintAsString(keyBindingCertificate);
            // Ask the key binding to search the database for a new certificate matching its public key
            final String boundCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
            
            // Try to make a new key binding giving the certificate fingerprint directly
            internalKeyBindingId1 = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME1, InternalKeyBindingStatus.ACTIVE, CertTools.getFingerprintAsString(keyBindingCertificate), cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
            InternalKeyBindingInfo info = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId1);
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), info.getCertificateId());

            // Try to make a new key binding giving the certificate fingerprint directly, but in upper case instead of the default lower case
            internalKeyBindingId2 = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME2, InternalKeyBindingStatus.ACTIVE, CertTools.getFingerprintAsString(keyBindingCertificate).toUpperCase(Locale.ENGLISH), cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
            info = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId2);
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), info.getCertificateId());
        } finally { 
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId1);
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId2);
            internalCertStoreSession.removeCertificate(certFpToDelete);
        }
    }

    @Test
    public void workflowIssueCertFromCsrUpdateAndRenew() throws Exception {
        final String TEST_METHOD_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String KEY_BINDING_NAME = TEST_METHOD_NAME;
        final String KEY_PAIR_ALIAS = TEST_METHOD_NAME;
        final String endEntityId = TESTCLASSNAME+"_" + TEST_METHOD_NAME;
        // Clean up old key binding
        removeInternalKeyBindingByName(alwaysAllowToken, TEST_METHOD_NAME);
        int internalKeyBindingId = 0;
        String certFpToDelete = null;
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
            final Map<String, Serializable> dataMap = new LinkedHashMap<String, Serializable>();
            dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap, null);
            // Add a user to EJBCA for the renewal later on
            final EndEntityInformation endEntityInformation = new EndEntityInformation(endEntityId, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            endEntityInformation.setPassword("foo123");
            // Request a CSR for the key pair
            final byte[] csr = internalKeyBindingMgmtSession.generateCsrForNextKey(alwaysAllowToken, internalKeyBindingId);
            RequestMessage req = new PKCS10RequestMessage(csr);
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, endEntityInformation, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
            certFpToDelete = CertTools.getFingerprintAsString(keyBindingCertificate);
            // Ask the key binding to search the database for a new certificate matching its public key
            final String boundCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
            // Since we no have a certificate issued by an internal CA, we should be able to renew it
            final String renewedCertificateFingerprint = internalKeyBindingMgmtSession.renewInternallyIssuedCertificate(alwaysAllowToken, internalKeyBindingId, endEntityInformation);
            assertNotNull("Renewal returned null which is an undefined state.", renewedCertificateFingerprint);
            assertFalse("After certificate renewal the same certificate was returned",
                    boundCertificateFingerprint.equals(renewedCertificateFingerprint));
            final String actualCertificateFingerprint = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId).getCertificateId();
            assertFalse("After certificate renewal the same certificate still in use.",
                    boundCertificateFingerprint.equals(actualCertificateFingerprint));
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            internalCertStoreSession.removeCertificate(certFpToDelete);
        }
    }

    @Test
    public void workflowIssueCertFromCsrAndImport() throws Exception {
        final String TEST_METHOD_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String KEY_BINDING_NAME = TEST_METHOD_NAME;
        final String KEY_PAIR_ALIAS = TEST_METHOD_NAME;
        // Clean up old key binding
        removeInternalKeyBindingByName(alwaysAllowToken, TEST_METHOD_NAME);
        int internalKeyBindingId = 0;
        String certFpToDelete = null;
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, null, null);
            log.debug("Created InternalKeyBinding with id " + internalKeyBindingId);
            // Request a CSR for the key pair
            final byte[] csr = internalKeyBindingMgmtSession.generateCsrForNextKey(alwaysAllowToken, internalKeyBindingId);
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), 1, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setPassword("foo123");
            RequestMessage req = new PKCS10RequestMessage(csr);
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                    X509ResponseMessage.class, signSession.fetchCertGenParams())).getCertificate());
            certFpToDelete = CertTools.getFingerprintAsString(keyBindingCertificate);
            // Import the issued certificate (since it is already in the database, only the pointer will be updated)
            internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId, keyBindingCertificate.getEncoded());
            // Fetch the InternalKeyBinding's current certificate mapping
            String boundCertificateFingerprint = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId).getCertificateId();
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            internalCertStoreSession.removeCertificate(certFpToDelete);
        }
    }

    private void removeInternalKeyBindingByName(AuthenticationToken authenticationToken, String name) throws AuthorizationDeniedException {
        // Clean up old key binding
        final Integer oldInternalKeyBindingId = internalKeyBindingMgmtSession.getIdFromName(name);
        if (oldInternalKeyBindingId != null && internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, oldInternalKeyBindingId)) {
            log.info("Removed keybinding with name " + name + ".");
        }
    }

}
