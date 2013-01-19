/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.authentication.tokens;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.authorization.user.AccessMatchType;
import org.cesecore.authorization.user.AccessUserAspect;
import org.cesecore.authorization.user.AccessUserAspectData;
import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.easymock.EasyMock;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Unit tests for the X509CertificateAuthenticationToken class. Note that this test class subverts the unit test concept slightly by using 'real'
 * certificates.
 * 
 * @version $Id$
 * 
 */
public class X509CertificateAuthenticationTokenTest {

    private KeyPair keys;
    private X509Certificate certificate;

    @BeforeClass
    public static void setUpCryptoProvider() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException,
            SignatureException, IllegalStateException, OperatorCreationException, CertificateException, IOException {
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        certificate = CertTools.genSelfCert(
                "C=Test,O=Test,CN=Test,DC=Test,L=Test,SN=Test,ST=Test,OU=Test,T=Test,UID=Test,E=Test,RFC822NAME=Test,UPN=Test", 365, null,
                keys.getPrivate(), keys.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
    }

    @After
    public void tearDown() {
        keys = null;
        certificate = null;
    }

    /**
     * Standard vanilla test for creating an X509CertificateAuthenticationToken.
     */
    @Test
    public void testCreateAuthenticationToken() {
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        X509CertificateAuthenticationToken authenticationToken = new X509CertificateAuthenticationToken(principals, credentials);
        assertTrue(authenticationToken != null);
    }

    /**
     * This test attempts to subvert X509CertificateAuthenticationToken's constructor by not supplying any credentials.
     */
    @Test
    public void testCreateAuthenticationTokenWithoutCredential() {
        X509CertificateAuthenticationToken authenticationToken = null;
        try {
            authenticationToken = new X509CertificateAuthenticationToken(new HashSet<X500Principal>(), new HashSet<X509Certificate>());
        } catch (InvalidAuthenticationTokenException e) {
            assertTrue(authenticationToken == null);
            return;
        }
        fail("X509CertificateAuthenticationToken was created without a certificate. This should not happen.");
    }

    /**
     * Attempt to create an authentication token with double certificates.
     * 
     * @throws NoSuchProviderException
     * @throws IllegalStateException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException 
     * @throws CertificateException 
     * @throws OperatorCreationException 
     */
    @Test
    public void testCreateAuthenticationTokenWithMultipleCredentials() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, IllegalStateException, NoSuchProviderException, OperatorCreationException, CertificateException, IOException {
        X509CertificateAuthenticationToken authenticationToken = null;

        X509Certificate secondCertificate = CertTools.genSelfCert("C=SE,O=Monkey,CN=Monkey", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        credentials.add(secondCertificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        principals.add(secondCertificate.getSubjectX500Principal());

        try {
            authenticationToken = new X509CertificateAuthenticationToken(new HashSet<X500Principal>(), new HashSet<X509Certificate>());
        } catch (InvalidAuthenticationTokenException e) {
            assertTrue(authenticationToken == null);
            return;
        }
        fail("X509CertificateAuthenticationToken was created multiple certificates. This should not happen.");
    }

    /**
     * Test matching with an incorrect CAID
     */
    @Test
    public void testMatchCaIdFail() {
        X509CertificateAuthenticationToken authenticationToken = getAuthenticationToken();
        AccessUserAspect accessUser = EasyMock.createMock(AccessUserAspectData.class);
        EasyMock.expect(accessUser.getCaId()).andReturn(-1).anyTimes();
        EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);
        EasyMock.replay(accessUser);
        assertFalse("AccessUser matched in spit of incorrect CaIDs", authenticationToken.matches(accessUser));
        EasyMock.verify(accessUser);
    }

    @Test
    public void testMatchWithFullDN() {
        AccessUserAspect accessUser;
        X509CertificateAuthenticationToken authenticationToken = getAuthenticationToken();
        int caid = (CertTools.stringToBCDNString(certificate.getIssuerDN().toString())).hashCode();
        
        accessUser = EasyMock.createMock(AccessUserAspectData.class);
        
        EasyMock.expect(accessUser.getCaId()).andReturn(caid);
        EasyMock.expect(accessUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_FULLDN.getNumericValue());
        EasyMock.expect(accessUser.getMatchValue()).andReturn(CertTools.getSubjectDN(certificate));
        EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASEINS);
        EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);
        EasyMock.replay(accessUser);
        
        assertTrue(authenticationToken.matches(accessUser));
        
        EasyMock.verify(accessUser);
    }
    
    /**
     * Test matching with the rest of the vile lot.
     * 
     */
    @Test
    public void testMatchWithAllValues() {
        X509CertificateAuthenticationToken authenticationToken = getAuthenticationToken();
        int caid = (CertTools.stringToBCDNString(certificate.getIssuerDN().toString())).hashCode();
        AccessUserAspect accessUser;
        X500PrincipalAccessMatchValue[] allValues = X500PrincipalAccessMatchValue.values();
        for (X500PrincipalAccessMatchValue matchValue : allValues) {
            switch (matchValue) {
            case WITH_SERIALNUMBER:
                accessUser = EasyMock.createMock(AccessUserAspectData.class);
                EasyMock.expect(accessUser.getCaId()).andReturn(caid).times(2);
                EasyMock.expect(accessUser.getMatchWith()).andReturn(X500PrincipalAccessMatchValue.WITH_SERIALNUMBER.getNumericValue()).times(2);
                EasyMock.expect(accessUser.getMatchValue()).andReturn(certificate.getSerialNumber().toString(16)).times(2);
                EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_EQUALCASEINS);
                EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(AccessMatchType.TYPE_NOT_EQUALCASEINS);
                EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE).times(2);
                EasyMock.replay(accessUser);
                // Try once for AccessMatchType.TYPE_EQUALCASE/TYPE_EQUALCASEINS
                assertTrue(authenticationToken.matches(accessUser));
                // Try again for TYPE_NOT_EQUALCASE/TYPE_NOT_EQUALCASEINS
                assertFalse(authenticationToken.matches(accessUser));
                EasyMock.verify(accessUser);
                break;
            case WITH_FULLDN:
                break;
            case WITH_RFC822NAME:
                break;
            case WITH_UPN:
                break;
            default:
                AccessMatchType match = AccessMatchType.values()[matchValue.ordinal() % 4];

                accessUser = EasyMock.createMock(AccessUserAspectData.class);
                EasyMock.expect(accessUser.getCaId()).andReturn(caid);

                EasyMock.expect(accessUser.getMatchWith()).andReturn(matchValue.getNumericValue());
                EasyMock.expect(accessUser.getMatchTypeAsType()).andReturn(match);
                EasyMock.expect(accessUser.getMatchValue()).andReturn("Test");
                EasyMock.expect(accessUser.getTokenType()).andReturn(X509CertificateAuthenticationToken.TOKEN_TYPE);
                EasyMock.replay(accessUser);
                if (match == AccessMatchType.TYPE_EQUALCASE || match == AccessMatchType.TYPE_EQUALCASEINS) {
                    assertTrue("Could not match for value " + matchValue, authenticationToken.matches(accessUser));
                } else {
                    assertFalse("False match for value " + matchValue, authenticationToken.matches(accessUser));
                }
                EasyMock.verify(accessUser);
                break;
            }
        }
    }

    /** Verify that the token does not match after serialization and deserialization. */
    @Test
    public void testAuthFailAfterSerialization() throws IOException, ClassNotFoundException {
        final X509CertificateAuthenticationToken authenticationToken = getAuthenticationToken();
        int caid = (CertTools.stringToBCDNString(certificate.getIssuerDN().toString())).hashCode();
        final AccessUserAspect accessUser = new AccessUserAspectData("testRole", caid, X500PrincipalAccessMatchValue.WITH_SERIALNUMBER, AccessMatchType.TYPE_EQUALCASEINS, CertTools.getSerialNumberAsString(certificate));
        // Verify happy path first
        assertTrue("Regular matching was not successful.", authenticationToken.matches(accessUser));
        // Simulate remote EJB call using serialization. This should destroy the "transient" shared secret.
        final ByteArrayOutputStream buf = new ByteArrayOutputStream();
        new ObjectOutputStream(buf).writeObject(authenticationToken);
        final X509CertificateAuthenticationToken authenticationToken2 = (X509CertificateAuthenticationToken) new ObjectInputStream(new ByteArrayInputStream(buf.toByteArray())).readObject();
        // Verify that the shared secret was destroyed by trying to match the object again.
        assertFalse("Shared secret in JVM was not destroyed in local object during serialization.", authenticationToken2.matches(accessUser));
    }

    /** Verify that the token does not match after serialization and deserialization. */
    @Test
    public void testBadSerialNumber() {
        final X509CertificateAuthenticationToken authenticationToken = getAuthenticationToken();
        int caid = (CertTools.stringToBCDNString(certificate.getIssuerDN().toString())).hashCode();
        final AccessUserAspect accessUser = new AccessUserAspectData("testRole", caid, X500PrincipalAccessMatchValue.WITH_SERIALNUMBER, AccessMatchType.TYPE_EQUALCASEINS, "qwerty_1");
        // Will always return false, but not throw an exception
        assertFalse("matching was succesful, should not have been.", authenticationToken.matches(accessUser));
    }

    /**
     * Produces a standard X509CertificateAuthenticationToken, for internal use.
     * 
     * @return a working X509CertificateAuthenticationToken.
     */
    private X509CertificateAuthenticationToken getAuthenticationToken() {
        Set<X509Certificate> credentials = new HashSet<X509Certificate>();
        credentials.add(certificate);
        Set<X500Principal> principals = new HashSet<X500Principal>();
        principals.add(certificate.getSubjectX500Principal());
        return new X509CertificateAuthenticationToken(principals, credentials);
    }
}
