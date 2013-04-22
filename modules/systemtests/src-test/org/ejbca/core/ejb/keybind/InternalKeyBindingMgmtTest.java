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
import static org.junit.Assert.assertTrue;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CaSessionTest;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.SoftCryptoToken;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.signer.InternalKeyBindingMgmtSession;
import org.ejbca.core.ejb.signer.InternalKeyBindingMgmtSessionRemote;
import org.ejbca.core.ejb.signer.InternalKeyBindingStatus;
import org.ejbca.core.ejb.signer.impl.OcspKeyBinding;
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
        x509ca = CaSessionTest.createTestX509CA("CN="+TESTCLASSNAME, "foo123".toCharArray(), false);
        // Remove any lingering test CA before starting the tests
        try {
            final int oldCaCryptoTokenId = caSession.getCAInfo(alwaysAllowToken, x509ca.getCAId()).getCAToken().getCryptoTokenId();
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, oldCaCryptoTokenId);
        } catch (CADoesntExistsException e) {
            // Ok. The old test run cleaned up everything properly.
        }
        caSession.removeCA(alwaysAllowToken, x509ca.getCAId());
        // Now add the test CA so it is available in the tests
        caSession.addCA(alwaysAllowToken, x509ca);
        // Remove any old CryptoToken created by this setup
        final Integer oldCryptoTokenId = cryptoTokenManagementSession.getIdFromName(TESTCLASSNAME);
        if (oldCryptoTokenId != null) {
            cryptoTokenManagementSession.deleteCryptoToken(alwaysAllowToken, oldCryptoTokenId.intValue());
        }
        // Create one additional CryptoToken to use from the tests below
        cryptoTokenId = cryptoTokenManagementSession.createCryptoToken(alwaysAllowToken, TESTCLASSNAME, SoftCryptoToken.class.getName(), null, null, "foo123".toCharArray());
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
        final Map<String, List<String>> availableTypesAndPropertyKeys = internalKeyBindingMgmtSession.getAvailableTypesAndPropertyKeys(alwaysAllowToken);
        assertTrue("Expected " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.", availableTypesAndPropertyKeys.containsKey(KEYBINDING_TYPE_ALIAS));
        // Verify that a property we intend to modify exists for our key binding implementation
        assertTrue("Expected " + KEYBINDING_TYPE_ALIAS + " to exist on the server for this test.", availableTypesAndPropertyKeys.get(KEYBINDING_TYPE_ALIAS).contains(PROPERTY_ALIAS));
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
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, dataMap);
            // Get the public key for the key pair currently used in the binding
            PublicKey publicKey = KeyTools.getPublicKeyFromBytes(internalKeyBindingMgmtSession.getNextPublicKeyForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId));
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
            user.setPassword("foo123");
            RequestMessage req = new SimpleRequestMessage(publicKey, user.getUsername(), user.getPassword());            
            X509Certificate keyBindingCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(alwaysAllowToken, user, req,
                    X509ResponseMessage.class)).getCertificate());
            // Ask the key binding to search the database for a new certificate matching its public key
            String boundCertificateFingerprint = internalKeyBindingMgmtSession.updateCertificateForInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
            // Verify that it was the right certificate it found
            assertEquals("Wrong certificate was found for InternalKeyBinding", CertTools.getFingerprintAsString(keyBindingCertificate), boundCertificateFingerprint);
            // ...so now we have a mapping between a certificate in the database and a key pair in a CryptoToken
        } finally {
            internalKeyBindingMgmtSession.deleteInternalKeyBinding(alwaysAllowToken, internalKeyBindingId);
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
                    KEY_BINDING_NAME, InternalKeyBindingStatus.ACTIVE, null, cryptoTokenId, KEY_PAIR_ALIAS, null);
            log.debug("Created InternalKeyBinding with id " + internalKeyBindingId);
            // Request a CSR for the key pair
            final byte[] csr = internalKeyBindingMgmtSession.generateCsrForNextKey(alwaysAllowToken, internalKeyBindingId);
            // Issue a certificate in EJBCA for the public key
            final EndEntityInformation user = new EndEntityInformation(TESTCLASSNAME+"_" + TEST_METHOD_NAME, "CN="+TESTCLASSNAME +"_" + TEST_METHOD_NAME, x509ca.getCAId(), null, null,
                    EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
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
