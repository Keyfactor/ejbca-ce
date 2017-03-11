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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.cesecore.RoleUsingTestCase;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authentication.tokens.X509CertificateAuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.cert.CrlExtensions;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.Base64;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests CRL store.
 *
 * @version $Id$
 */
public class CrlStoreSessionTest extends RoleUsingTestCase {

    private static KeyPair keys;

    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(CrlStoreSessionTest.class.getSimpleName());
    
    private static byte[] testcrl = Base64.decode(("MIIBjjB4AgEBMA0GCSqGSIb3DQEBBQUAMBUxEzARBgNVBAMMCkx1bmFDQTEwMjQX"
    		+"DTEwMTEyNTEwMzkwMFoXDTEwMTEyNjEwMzkwMFqgLzAtMB8GA1UdIwQYMBaAFHxk"
    		+"N9a5Vyro6OD5dXiAbqLfxXo3MAoGA1UdFAQDAgECMA0GCSqGSIb3DQEBBQUAA4IB"
    		+"AQCoEY8mTbUwFaHLWYNBhh9q07zhj+2UhN2q/JzJppPonkn8qwnFYAc0MXnLV3et"
    		+"TE10N40jx+wxhNzerKi5aPP5VugVZVPRCwhH3ObwZpzQToYaa/ypbXp/7Pnz6K2Y"
    		+"n4NVbutNKreBRyoXmyuRB5YaiJII1lTHLOu+NCkUTREVCE3xd+OQ258TTW+qgUgy"
    		+"u0VnpowMyEwfkxZQkVXI+9woowKvu07DJmG7pNeAZWRT8ff1pzCERB39qUJExVcn"
    		+"g9LkoIo1SpZnHh+oELNJA0PrjYdVzerkG9fhtzo54dVDp9teVUHuJOp9NAG9U3XW"
    		+"bBc+OH6NrfpkCWsw9WLdrOK2").getBytes());

    private static byte[] testdeltacrl = Base64.decode(("MIIBnjCBhwIBATANBgkqhkiG9w0BAQUFADAVMRMwEQYDVQQDDApMdW5hQ0ExMDI0"
    		+"Fw0xMTAyMjgwOTIwNDNaFw0xMTAyMjgyMTIwNDNaoD4wPDAfBgNVHSMEGDAWgBR8"
    		+"ZDfWuVcq6Ojg+XV4gG6i38V6NzAKBgNVHRQEAwIBAzANBgNVHRsBAf8EAwIBAjAN"
    		+"BgkqhkiG9w0BAQUFAAOCAQEAe1LESh0Ms+fRQwWnbn53c4bRtNshHeIHUM1Ysys2"
    		+"i6gOyHKGUsh1MJWikzKA+HiVRdgH9ZKKnzJrk7Ir11cRiD2iSml8nWkDEeK6IA4W"
    		+"S01izet5iRMP7sSZAlWB8ty+yDAb5ems8hXBPvS/17aWXUfAG4pTD0o8S7ya+pCw"
    		+"AwjbI6Uv7QiGt8tVzqe6zf6qNBh4zNChpyxFfRsnVRjnseUzTeyT+eGOr/vGi9dZ"
    		+"vWEP4Di6e9jpp+lIDRVRr72fw/D68j9dz5juq4wgnoh5ueQLUqThOTEB7Hd4R4LY"
    		+"WhGWznjJBqsCCgGAvHfQBDeT4p+k8TrnJswyfXJCrGPZcQ==").getBytes());

    @BeforeClass
    public static void setUpProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
        keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
    }

    @Before
    public void setUp() throws Exception {
    	// Set up base role that can edit roles
        super.setUpAuthTokenAndRole(null, this.getClass().getSimpleName(), Arrays.asList(StandardRules.CAACCESSBASE.resource()), null);
    	removeTestCrls();
    }

    @After
    public void cleanUp() throws Exception {
    	try {
    	    removeTestCrls();
    	} finally {
    		// Be sure to to this, even if the above fails
    	    super.tearDownRemoveRole();
    	}
    }
    
    /** Remove any lingering test CRLs persisted by this test */
    private void removeTestCrls() throws CRLException, AuthorizationDeniedException {
        X509CRL crl = CertTools.getCRLfromByteArray(testcrl);
        String fingerprint = CertTools.getFingerprintAsString(crl);
        internalCertStoreSession.removeCRL(alwaysAllowToken, fingerprint);
        X509CRL deltacrl = CertTools.getCRLfromByteArray(testdeltacrl);
        String deltaFingerprint = CertTools.getFingerprintAsString(deltacrl);
        internalCertStoreSession.removeCRL(alwaysAllowToken, deltaFingerprint);
    }

    @Test
    public void testStoreAndReadCRL() throws Exception {
    	X509CRL crl = CertTools.getCRLfromByteArray(testcrl);    	
    	BigInteger crlnumber = CrlExtensions.getCrlNumber(crl);
    	String issuerDN = CertTools.getIssuerDN(crl);
    	String fingerprint = CertTools.getFingerprintAsString(crl);
    	crlStoreSession.storeCRL(roleMgmgToken, crl.getEncoded(), fingerprint, crlnumber.intValue(), issuerDN, crl.getThisUpdate(), crl.getNextUpdate(), -1);
    	CRLInfo info = crlStoreSession.getCRLInfo(fingerprint);
    	assertEquals(crlnumber.intValue(), info.getLastCRLNumber());
    	assertEquals(issuerDN, info.getSubjectDN());
    	assertEquals(crl.getThisUpdate(), info.getCreateDate());
    	assertEquals(crl.getNextUpdate(), info.getExpireDate());
    	
    	X509CRL deltacrl = CertTools.getCRLfromByteArray(testdeltacrl);
    	BigInteger deltaCrlnumber = CrlExtensions.getCrlNumber(deltacrl);
    	String deltaIssuerDN = CertTools.getIssuerDN(deltacrl);    
    	String deltaFingerprint = CertTools.getFingerprintAsString(deltacrl);
    	crlStoreSession.storeCRL(roleMgmgToken, deltacrl.getEncoded(), deltaFingerprint, deltaCrlnumber.intValue(), deltaIssuerDN, deltacrl.getThisUpdate(), deltacrl.getNextUpdate(), 1);
    	info = crlStoreSession.getCRLInfo(deltaFingerprint);
    	assertEquals(deltaCrlnumber.intValue(), info.getLastCRLNumber());
    	assertEquals(deltaIssuerDN, info.getSubjectDN());
    	assertEquals(deltacrl.getThisUpdate(), info.getCreateDate());
    	assertEquals(deltacrl.getNextUpdate(), info.getExpireDate());

    	info = crlStoreSession.getLastCRLInfo(issuerDN, false);
    	assertEquals(crlnumber.intValue(), info.getLastCRLNumber());
    	assertEquals(issuerDN, info.getSubjectDN());
    	assertEquals(crl.getThisUpdate(), info.getCreateDate());
    	assertEquals(crl.getNextUpdate(), info.getExpireDate());
    	
    	info = crlStoreSession.getLastCRLInfo(issuerDN, true);
    	assertEquals(deltaCrlnumber.intValue(), info.getLastCRLNumber());
    	assertEquals(deltaIssuerDN, info.getSubjectDN());
    	assertEquals(deltacrl.getThisUpdate(), info.getCreateDate());
    	assertEquals(deltacrl.getNextUpdate(), info.getExpireDate());
    	
    	int number = crlStoreSession.getLastCRLNumber(issuerDN, false);
    	assertEquals(2, number); // crlnumber.intValue()
    	number = crlStoreSession.getLastCRLNumber(issuerDN, true);
    	assertEquals(3, number); // deltaCrlnumber.intValue()
    	
    	byte[] crlbytes = crlStoreSession.getLastCRL(issuerDN, false);
    	assertNotNull(crlbytes);
    	assertEquals(fingerprint, CertTools.getFingerprintAsString(crlbytes));
    	crlbytes = crlStoreSession.getLastCRL( issuerDN, true);
    	assertNotNull(crlbytes);
    	assertEquals(deltaFingerprint, CertTools.getFingerprintAsString(crlbytes));

    	// Get by CRL number
        crlbytes = crlStoreSession.getCRL(issuerDN, crlnumber.intValue());
        assertNotNull(crlbytes);
        assertEquals(fingerprint, CertTools.getFingerprintAsString(crlbytes));
        crlbytes = crlStoreSession.getCRL( issuerDN, deltaCrlnumber.intValue());
        assertNotNull(crlbytes);
        assertEquals(deltaFingerprint, CertTools.getFingerprintAsString(crlbytes));
    	
    }

    /** Test error handling when we request info that does not exist. */
    @Test
    public void testCrlStoreSessionErrorHandling() {
    	assertNull("crlStoreSession.getLastCRL returned a CRL for nonexsting CA", crlStoreSession.getLastCRL("CN=notexsting", false));
    	assertNull("crlStoreSession.getLastCRL returned a DeltaCRL for nonexsting CA", crlStoreSession.getLastCRL("CN=notexsting", true));
    	assertNull("crlStoreSession.getLastCRLInfo returned CRLInfo for nonexsting CA", crlStoreSession.getLastCRLInfo("CN=notexsting", false));
    	assertNull("crlStoreSession.getLastCRLInfo returned Delta CRLInfo for nonexsting CA", crlStoreSession.getLastCRLInfo("CN=notexsting", true));
    	assertNull("crlStoreSession.getCRLInfo returned CRLInfo for nonexsting CRL fingerprint", crlStoreSession.getCRLInfo("tooshortfp"));
    }


	@Test
	public void testAuthorization() throws Exception {
        
        X509Certificate certificate = CertTools.genSelfCert("C=SE,O=Test,CN=Test CrlStoreSessionNoAuth", 365, null, keys.getPrivate(), keys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, true);
        AuthenticationToken adminTokenNoAuth = new X509CertificateAuthenticationToken(certificate);
        
    	X509CRL crl = CertTools.getCRLfromByteArray(testcrl);    	
    	BigInteger crlnumber = CrlExtensions.getCrlNumber(crl);
    	String issuerDN = CertTools.getIssuerDN(crl);
    	String fingerprint = CertTools.getFingerprintAsString(crl);

    	// Make sure we don't have the CRL stored
    	internalCertStoreSession.removeCRL(roleMgmgToken, fingerprint);

    	// Try to store a CRL with an admin that does not have access to CA
        try {
        	crlStoreSession.storeCRL(adminTokenNoAuth, crl.getEncoded(), fingerprint, crlnumber.intValue(), issuerDN, crl.getThisUpdate(), crl.getNextUpdate(), -1);
        	assertTrue("Should throw", false);
        } catch (AuthorizationDeniedException e) {
        	// NOPMD
        }
    	CRLInfo info = crlStoreSession.getCRLInfo(fingerprint);
    	assertNull(info);
    	// Store it for real
    	crlStoreSession.storeCRL(roleMgmgToken, crl.getEncoded(), fingerprint, crlnumber.intValue(), issuerDN, crl.getThisUpdate(), crl.getNextUpdate(), -1);
    	info = crlStoreSession.getCRLInfo(fingerprint);
    	assertNotNull(info);
    	// Remove the CRL
    	internalCertStoreSession.removeCRL(roleMgmgToken, fingerprint);
    	info = crlStoreSession.getCRLInfo(fingerprint);
    	assertNull(info);
	}
}
