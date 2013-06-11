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
package org.ejbca.core.ejb.keybind;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.Serializable;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.persistence.PersistenceException;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.keybind.impl.OcspKeyBinding;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.util.TraceLogMethodsRule;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

/**
 * @see InternalKeyBindingMgmtSession
 * @version $Id$
 */
public class InternalKeyBindingMgmtTest {

    private static final Logger log = Logger.getLogger(InternalKeyBindingMgmtTest.class);
    private static final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(InternalKeyBindingMgmtTest.class.getSimpleName()));
    private static final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CryptoTokenManagementSessionRemote.class);
    private static final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private static final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    
    private static final String TESTCLASSNAME = InternalKeyBindingMgmtTest.class.getSimpleName();
    private static final String KEYBINDING_TYPE_ALIAS = OcspKeyBinding.IMPLEMENTATION_ALIAS;
    private static final String PROPERTY_ALIAS = OcspKeyBinding.PROPERTY_NON_EXISTING_GOOD;

    private static X509CA x509ca = null;
    private static int cryptoTokenId = 0;

    @Rule
    public TestRule traceLogMethodsRule = new TraceLogMethodsRule();
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        CryptoProviderTools.installBCProvider();
        x509ca = CryptoTokenTestUtils.createTestCA(alwaysAllowToken, "CN="+TESTCLASSNAME);
        cryptoTokenId = CryptoTokenTestUtils.createCryptoToken(alwaysAllowToken, TESTCLASSNAME);
    }

    @AfterClass
    public static void afterClass() throws Exception {
        cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, cryptoTokenId);
        if (x509ca != null) {
            final int caCryptoTokenId = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, caCryptoTokenId);
            caSession.removeCA(alwaysAllowToken, x509ca.getCAId());
        }
    }

    @Before
    public void setUp() throws Exception {
    }

    @After
    public void tearDown() throws Exception {
    }

    @Test
    public void assertTestPreRequisites() throws Exception {
        // Request all available implementations from server and verify that the implementation we intend to use exists
        final Map<String, List<InternalKeyBindingProperty<? extends Serializable>>> availableTypesAndProperties = internalKeyBindingMgmtSession.getAvailableTypesAndProperties(alwaysAllowToken);
        final List<InternalKeyBindingProperty<? extends Serializable>> availableProperties = availableTypesAndProperties.get(KEYBINDING_TYPE_ALIAS);
        assertNotNull("Expected " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.", availableProperties);
        // Verify that a property we intend to modify exists for our key binding implementation
        boolean exists = false;
        for (final InternalKeyBindingProperty<? extends Serializable> property : availableProperties) {
            if (property.getName().equals(PROPERTY_ALIAS)) {
                exists = true;
                break;
            }
        }
        assertTrue("Expected property " + PROPERTY_ALIAS + " in " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.", exists);
    }
    
    @Test
    public void workflowIssueCertFromPublicKeyAndUpdate() throws Exception {
        final String TEST_METHOD_NAME = Thread.currentThread().getStackTrace()[1].getMethodName();
        final String KEY_BINDING_NAME = TEST_METHOD_NAME;
        final String KEY_PAIR_ALIAS = TEST_METHOD_NAME;
        // Clean up old key binding
        removeInternalKeyBindingByName(alwaysAllowToken, TEST_METHOD_NAME);
        int internalKeyBindingId = 0;
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
            final Map<Object,Object> dataMap = new LinkedHashMap<Object,Object>();
            dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap);
            // Get the public key for the key pair currently used in the binding
            PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId));
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setPassword("foo123");
            RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());            
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                    X509ResponseMessage.class)).getCertificate());
            // Ask the key binding to search the database for a new certificate matching its public key
            final String boundCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
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
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            // Create a new InternalKeyBinding with a implementation specific property and bind it to the previously generated key
            final Map<Object,Object> dataMap = new LinkedHashMap<Object,Object>();
            dataMap.put(PROPERTY_ALIAS, Boolean.FALSE);
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, dataMap);
            // Add a user to EJBCA for the renewal later on
            final EndEntityInformation endEntityInformation = new EndEntityInformation(endEntityId, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            endEntityInformation.setPassword("foo123");
            try {
                endEntityManagementSession.addUser(alwaysAllowToken, endEntityInformation, false);
            } catch (PersistenceException e) {
                // The user might exist from a previous test run, just change it if so
                endEntityManagementSession.changeUser(alwaysAllowToken, endEntityInformation, false);
            }
            // Request a CSR for the key pair
            final byte[] csr = internalKeyBindingMgmtSession.generateCsrForNextKey(alwaysAllowToken, internalKeyBindingId);
            RequestMessage req = new PKCS10RequestMessage(csr);
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, endEntityInformation, req,
                    X509ResponseMessage.class)).getCertificate());
            // Ask the key binding to search the database for a new certificate matching its public key
            final String boundCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
            // Since we no have a certificate issued by an internal CA, we should be able to renew it
            final String renewedCertificateFingerprint = internalKeyBindingMgmtSession.renewInternallyIssuedCertificate(alwaysAllowToken, internalKeyBindingId);
            assertNotNull("Renewal returned null which is an undefined state.", renewedCertificateFingerprint);
            assertFalse("After certificate renewal the same certificate was returned",
                    boundCertificateFingerprint.equals(renewedCertificateFingerprint));
            final String actualCertificateFingerprint = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId).getCertificateId();
            assertFalse("After certificate renewal the same certificate still in use.",
                    boundCertificateFingerprint.equals(actualCertificateFingerprint));
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            try {
                endEntityManagementSession.deleteUser(alwaysAllowToken, endEntityId);
            } catch (NotFoundException e) {
                log.debug("Clean up failed.", e);
            }
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
        try {
            // First create a new CryptoToken
            cryptoTokenManagementSession.createKeyPair(alwaysAllowToken, cryptoTokenId, KEY_PAIR_ALIAS, "RSA2048");
            internalKeyBindingId = internalKeyBindingMgmtSession.createInternalKeyBinding(alwaysAllowToken, KEYBINDING_TYPE_ALIAS,
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, AlgorithmConstants.SIGALG_SHA1_WITH_RSA, null);
            log.debug("Created InternalKeyBinding with id " + internalKeyBindingId);
            // Request a CSR for the key pair
            final byte[] csr = internalKeyBindingMgmtSession.generateCsrForNextKey(alwaysAllowToken, internalKeyBindingId);
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER,
                    EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setPassword("foo123");
            RequestMessage req = new PKCS10RequestMessage(csr);
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                    X509ResponseMessage.class)).getCertificate());
            // Import the issued certificate (since it is already in the database, only the pointer will be updated)
            internalKeyBindingMgmtSession.importCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId, keyBindingCertificate.getEncoded());
            // Fetch the InternalKeyBinding's current certificate mapping
            String boundCertificateFingerprint = internalKeyBindingMgmtSession.getInternalKeyBindingInfo(alwaysAllowToken, internalKeyBindingId).getCertificateId();
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
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
