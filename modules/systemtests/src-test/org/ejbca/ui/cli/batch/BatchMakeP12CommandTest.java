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

package org.ejbca.ui.cli.batch;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;

import org.apache.commons.io.FileUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.NotFoundException;
import org.junit.After;
import org.junit.Before;
import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runners.MethodSorters;

/** Tests the batch making of soft cards.
 *
 */
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class BatchMakeP12CommandTest extends CaTestCase {
    private static final Logger log = Logger.getLogger(BatchMakeP12CommandTest.class);
    private static final AuthenticationToken admin = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("BatchMakeP12Test"));
    private int caid = getTestCAId();

    private final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityManagementSessionRemote.class);
    private final EndEntityAccessSessionRemote endEntityAccessSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(EndEntityAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(
            InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final String username1 = BatchMakeP12CommandTest.class.getSimpleName() + "1";
    private final String username2 = BatchMakeP12CommandTest.class.getSimpleName() + "2";

    @Override
    @Before
    public void setUp() throws Exception {
        super.setUp();
        log.trace(">test01CreateNewUser()");
  
        endEntityManagementSession.addUser(admin, username1, "foo123", "C=SE, O=AnaTom, CN=" + username1, "", username1 + "@anatom.se", false,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_P12, caid);
        endEntityManagementSession.setClearTextPassword(admin, username1, "foo123");

        log.debug("created " + username1 + ", pwd=foo123");
        assertEquals("end entity password wasn't set", "foo123", findPassword(username1));

        endEntityManagementSession.addUser(admin, username2, "foo123", "C=SE, O=AnaTom, CN=" + username2, "", username2 + "@anatom.se", false,
                EndEntityConstants.EMPTY_END_ENTITY_PROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, EndEntityTypes.ENDUSER.toEndEntityType(),
                SecConst.TOKEN_SOFT_P12, caid);
        endEntityManagementSession.setClearTextPassword(admin, username2, "foo123");

        log.debug("created " + username2 + ", pwd=foo123");
        assertEquals("end entity password wasn't set", "foo123", findPassword(username2));
        log.trace("<test01CreateNewUsers()");
    }

    @Override
    @After
    public void tearDown() throws Exception {
        super.tearDown();
        if (endEntityAccessSession.findUser(admin, username1) != null) {
            endEntityManagementSession.deleteUser(admin, username1);
        }
        if (endEntityAccessSession.findUser(admin, username2) != null) {
            endEntityManagementSession.deleteUser(admin, username2);
        }
        internalCertStoreSession.removeCertificatesByUsername(username1);
        internalCertStoreSession.removeCertificatesByUsername(username2);
    }


    /**
     * Tests creation of P12 file
     *
     * @throws Exception error
     */
    @Test
    public void testMakeP12All() throws Exception {
        BatchMakeP12Command makep12 = new BatchMakeP12Command();
        File tmpfile = File.createTempFile("ejbca", "p12");
        makep12.execute("-dir", tmpfile.getParent());
        assertTrue("No file was created.", tmpfile.exists());
        EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
        EndEntityInformation user2 = endEntityAccessSession.findUser(admin, username1);
        assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus()); 
        assertEquals("User2 was not generated.", EndEntityConstants.STATUS_GENERATED, user2.getStatus()); 
    }

    @Test
    public void testMakeP12ForSingleUserDefaultRSA() throws Exception {
        Path tempDir = Files.createTempDirectory("ejbca");
        try {
            final BatchMakeP12Command makep12 = new BatchMakeP12Command();
            makep12.execute("-dir", tempDir.toString(), "--username", username1);
            assertTrue("No file was created.", tempDir.getNameCount() > 0);
            final EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
            assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus());
            // Check the generated keystore
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(tempDir.toString()+"/"+username1+".p12"), "foo123".toCharArray());
            final Key privKey = store.getKey(username1, "foo123".toCharArray());
            assertNotNull("No private key with alias '" + username1 + "' found in generated PKCS#12 file", privKey);
            final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
            assertEquals("Should have generated RSA keys by default", PKCSObjectIdentifiers.rsaEncryption.getId(), pkInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());            
        } finally {
            FileUtils.deleteDirectory(tempDir.toFile());
        }
    }

    @Test
    public void testMakeP12ForSingleUserECDSA() throws Exception {
        Path tempDir = Files.createTempDirectory("ejbca");
        try {
            final BatchMakeP12Command makep12 = new BatchMakeP12Command();
            makep12.execute("-dir", tempDir.toString(), "--username", username1, "--keyalg", "ECDSA", "--keyspec", "prime256v1");
            assertTrue("No file was created.", tempDir.getNameCount() > 0);
            final EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
            assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus());
            // Check the generated keystore
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(tempDir.toString()+"/"+username1+".p12"), "foo123".toCharArray());
            final Key privKey = store.getKey(username1, "foo123".toCharArray());
            assertNotNull("No private key with alias '" + username1 + "' found in generated PKCS#12 file", privKey);
            final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
            assertEquals("Should have generated ECDSA keys by default", X9ObjectIdentifiers.id_ecPublicKey.getId(), pkInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());            
        } finally {
            FileUtils.deleteDirectory(tempDir.toFile());
        }
    }
    
    @Test
    public void testMakeP12ForSingleUserEdDSA25519() throws Exception {
        Path tempDir = Files.createTempDirectory("ejbca");
        try {
            final BatchMakeP12Command makep12 = new BatchMakeP12Command();
            makep12.execute("-dir", tempDir.toString(), "--username", username1, "--keyalg", "Ed25519", "--keyspec", "ED25519");
            assertTrue("No file was created.", tempDir.getNameCount() > 0);
            final EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
            assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus());
            // Check the generated keystore
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(tempDir.toString()+"/"+username1+".p12"), "foo123".toCharArray());
            final Key privKey = store.getKey(username1, "foo123".toCharArray());
            assertNotNull("No private key with alias '" + username1 + "' found in generated PKCS#12 file", privKey);
            final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
            assertEquals("Should have generated EdDSA keys by default", EdECObjectIdentifiers.id_Ed25519.getId(), pkInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());            
        } finally {
            FileUtils.deleteDirectory(tempDir.toFile());
        }
    }
    
    
    @Test
    public void testMakeP12ForSingleUserEdDSA448() throws Exception {
        Path tempDir = Files.createTempDirectory("ejbca");
        try {
            final BatchMakeP12Command makep12 = new BatchMakeP12Command();
            makep12.execute("-dir", tempDir.toString(), "--username", username1, "--keyalg", "Ed448", "--keyspec", "ED448");
            assertTrue("No file was created.", tempDir.getNameCount() > 0);
            final EndEntityInformation user1 = endEntityAccessSession.findUser(admin, username1);
            assertEquals("User1 was not generated.", EndEntityConstants.STATUS_GENERATED, user1.getStatus());
            // Check the generated keystore
            final KeyStore store = KeyStore.getInstance("PKCS12");
            store.load(new FileInputStream(tempDir.toString()+"/"+username1+".p12"), "foo123".toCharArray());
            final Key privKey = store.getKey(username1, "foo123".toCharArray());
            assertNotNull("No private key with alias '" + username1 + "' found in generated PKCS#12 file", privKey);
            final PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(privKey.getEncoded());
            assertEquals("Should have generated EdDSA keys by default", EdECObjectIdentifiers.id_Ed448.getId(), pkInfo.getPrivateKeyAlgorithm().getAlgorithm().getId());            
        } finally {
            FileUtils.deleteDirectory(tempDir.toFile());
        }
    }
    

    /**
     * Gets the clear text password of a user.
     */
    private String findPassword(String user) throws Exception {
        EndEntityInformation ei = endEntityAccessSession.findUser(admin, user);
        if (ei == null) {
            throw new NotFoundException("coundn't find user \"" + user + "\"");
        }
        return ei.getPassword();
    }

    @Override
    public String getRoleName() {
        return this.getClass().getSimpleName();
    }
}
