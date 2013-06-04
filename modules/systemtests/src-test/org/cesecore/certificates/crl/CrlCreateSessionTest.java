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
package org.cesecore.certificates.crl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaTestSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class CrlCreateSessionTest extends CaTestCase {

    private static final Logger log = Logger.getLogger(CrlCreateSessionTest.class);
    
    private CaTestSessionRemote caTestSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CaTestSessionRemote.class);
    private CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    
    private AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(getRoleName());
    
    @BeforeClass
    public static void beforeClass() throws Exception {
        createTestCA();
    }
    
    @AfterClass
    public static void afterClass() throws Exception {
        removeTestCA();
    }
    
    @Test
    public void createCrl() throws CADoesntExistsException, AuthorizationDeniedException, CryptoTokenOfflineException {
        CA ca = caTestSessionRemote.getCA(authenticationToken, getTestCAId());
        final String certSubjectDN = CertTools.getSubjectDN(ca.getCACertificate()); 
        Collection<RevokedCertInfo> revcerts = certificateStoreSession.listRevokedCertInfo(certSubjectDN, -1);
        int fullnumber = crlStoreSession.getLastCRLNumber(certSubjectDN, false);
        int deltanumber = crlStoreSession.getLastCRLNumber(certSubjectDN, true);
        // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
        int nextCrlNumber = ( (fullnumber > deltanumber) ? fullnumber : deltanumber ) +1; 
        
        crlCreateSession.generateAndStoreCRL(authenticationToken, ca, revcerts, -1, nextCrlNumber);
            // We should now have a CRL generated
            byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
        try {
            assertNotNull(crl);
            // Check that it is signed by the correct public key
            X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
            PublicKey pubK = ca.getCACertificate().getPublicKey();
            xcrl.verify(pubK);
        } catch (Exception e) {
            log.error("Error: ", e);
            fail("Should not throw here");
        } finally {
            // Remove it to clean database
            internalCertificateStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(crl));
        }
    }

    @Override
    public String getRoleName() {
        return CrlCreateSessionTest.class.getSimpleName();
    }
    
}

// Test generate a CRL as well
// We should not have any CRL generated now
/*
byte[] crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
assertNull(crl);
try {
    // Create a CRL with this PKCS11 CA
    boolean result = crlCreateSession.forceCRL(roleMgmgToken, ca.getCAId());
    assertTrue(result);
    // We should now have a CRL generated
    crl = crlStoreSession.getLastCRL(ca.getSubjectDN(), false);
    assertNotNull(crl);         
    // Check that it is signed by the correct public key
    X509CRL xcrl = CertTools.getCRLfromByteArray(crl);
    xcrl.verify(pubK);
} catch (Exception e) {
    log.error("Error: ", e);
    assertTrue("Should not throw here", false);
} finally {
    // Remove it to clean database
    internalCertStoreSession.removeCRL(roleMgmgToken, CertTools.getFingerprintAsString(crl));           
}*/