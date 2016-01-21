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
package org.cesecore.certificates.certificate;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.ejb.FinderException;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.CertificateRevocationStatusVerifier;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.protocol.ocsp.OcspJunitHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class CertRevocationStatusCheckTest extends CaTestCase {

    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CertRevocationStatusCheckTest"));
    private static final Logger log = Logger.getLogger(CertRevocationStatusCheckTest.class);
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private GlobalConfigurationSessionRemote globalConfigSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
    private EndEntityManagementSessionRemote eeManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private CertificateStoreSessionRemote certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);

    
    private static final String CADN = "CN=CertRevocationStatusCheckTest";
    private CA testx509ca;

    @Before
    public void setUp() throws Exception {
        testx509ca = CaTestUtils.createTestX509CA(CADN, null, false);
        caSession.addCA(alwaysAllowToken, testx509ca);
        X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
        GlobalConfiguration gc = (GlobalConfiguration) globalConfigSession.getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID);
        URL crlUrl = new URL(gc.getStandardCRLDistributionPointURINoDN() + cainfo.getSubjectDN());
        cainfo.setDefaultCRLDistPoint(crlUrl.toString());
        //http://localhost:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=ManagementCA,O=EJBCA%20Sample,C=SE
        caSession.editCA(alwaysAllowToken, cainfo);


    }
    
    @After
    public void tearDown() throws Exception {
        try {
            // Remove any testca before exiting tests
            Certificate testX509caCert = testx509ca.getCACertificate();
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
            caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
            internalCertStoreSession.removeCertificate(testX509caCert);
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
        }
    }

    @Test
    public void test01VerificationWithCRL() throws Exception {
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        String crlFp1="", crlFp2="";
        
        try {
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId());
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
        
            final X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
            
            // Generate CRL
            Collection<RevokedCertInfo> revcerts = certStoreSession.listRevokedCertInfo(CADN, -1);
            int fullnumber = crlStoreSession.getLastCRLNumber(CADN, false);
            int deltanumber = crlStoreSession.getLastCRLNumber(CADN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            int nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;
            crlCreateSession.generateAndStoreCRL(alwaysAllowToken, testx509ca, revcerts, -1, nextCrlNumber);
            // We should now have a CRL generated
            byte[] crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
            crlFp1 = CertTools.getFingerprintAsString(crl);
            
            // Check usercert revocation status
            CertificateRevocationStatusVerifier verifier = new CertificateRevocationStatusVerifier(cainfo.getDefaultCRLDistPoint());
            boolean isRevoked = verifier.isCertificateRevoked(usercert, null);
            assertFalse(isRevoked);
            
            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), cainfo.getSubjectDN(), 0);
            
            // Generate a new CRL. It should contain usercert
            revcerts = certStoreSession.listRevokedCertInfo(CADN, -1);
            fullnumber = crlStoreSession.getLastCRLNumber(CADN, false);
            deltanumber = crlStoreSession.getLastCRLNumber(CADN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;
            crlCreateSession.generateAndStoreCRL(alwaysAllowToken, testx509ca, revcerts, -1, nextCrlNumber);
            crl = crlStoreSession.getLastCRL(testx509ca.getSubjectDN(), false);
            crlFp2 = CertTools.getFingerprintAsString(crl);
            
            // Check usercert revocation status
            isRevoked = verifier.isCertificateRevoked(usercert, null);
            assertTrue(isRevoked);
            
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp1);
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp2);
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }

    }
    
    @Test
    public void test02VerificationWithOCSP() throws Exception {
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        
        String baseUrl = "http://127.0.0.1:8080/ejbca";
        String resourceOcsp = "publicweb/status/ocsp";
        OcspJunitHelper helper = new OcspJunitHelper(baseUrl, resourceOcsp);
        helper.reloadKeys();
        
        try {
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId());
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
                
            // Check usercert revocation status
            CertificateRevocationStatusVerifier verifier = new CertificateRevocationStatusVerifier(
                    CertificateRevocationStatusVerifier.VERIFICATION_METHOD_OCSP, baseUrl+"/"+resourceOcsp); // "http://127.0.0.1:8080/ejbca/publicweb/status/ocsp"
            Boolean isRevoked = verifier.isCertificateRevoked(usercert, (X509Certificate) testx509ca.getCACertificate());
            assertNotNull(isRevoked);
            assertFalse(isRevoked);
            
            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), CADN, 0);
                
            // Check usercert revocation status
            isRevoked = verifier.isCertificateRevoked(usercert, (X509Certificate) testx509ca.getCACertificate());
            assertTrue(isRevoked);
                
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }
    
    
    private void createUser(String username, String dn, int caid) throws AuthorizationDeniedException,
                UserDoesntFullfillEndEntityProfile, WaitingForApprovalException, EjbcaException, FinderException, CADoesntExistsException {
        final EndEntityInformation user = new EndEntityInformation(username, dn, caid, null, username + "@primekey.se",
                new EndEntityType(EndEntityTypes.ENDUSER), SecConst.EMPTY_ENDENTITYPROFILE, 
                CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER, SecConst.TOKEN_SOFT_PEM, 0, null);
        user.setPassword("foo123");
        log.debug("Trying to add/edit USER: " + user.getUsername() + ", foo123, " + dn);
        try {
            eeManagementSession.addUser(alwaysAllowToken, user, true);
        } catch (Exception e) {
            log.debug("USER already exists: " + user.getUsername() + ", foo123, " + dn);
            eeManagementSession.changeUser(alwaysAllowToken, user, true);
            eeManagementSession.setUserStatus(alwaysAllowToken, user.getUsername(), EndEntityConstants.STATUS_NEW);
            log.debug("Reset status to NEW");
        }
    }
   
    @Override
    public String getRoleName() {
        return "CertRevocationStatusCheckTest";
    }

}
