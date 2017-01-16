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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;

import java.net.URL;
import java.security.KeyPair;
import java.security.cert.CRL;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.X509CA;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.CrlCreateSessionRemote;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.keys.token.CryptoTokenTestUtils;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.keys.util.PublicKeyWrapper;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.PKIXCertRevocationStatusChecker;
import org.ejbca.core.ejb.ca.CaTestCase;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.ocsp.OcspJunitHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests PKIXCertRevocationStatusChecker
 * 
 * @version $Id$
 */
public class CertRevocationStatusCheckerTest extends CaTestCase {

    @Override
    public String getRoleName() {
        return "CertRevocationStatusCheckerTest";
    }
    
    private final AuthenticationToken alwaysAllowToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal(
            "CertRevocationStatusCheckTest"));
    private static final Logger log = Logger.getLogger(CertRevocationStatusCheckerTest.class);
    
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private EndEntityManagementSessionRemote eeManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
    private SignSessionRemote signSession = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private CertificateStoreSessionRemote certStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CrlStoreSessionRemote crlStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
    private CrlCreateSessionRemote crlCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlCreateSessionRemote.class);
    private CertificateProfileSessionRemote certProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
    private EndEntityProfileSessionRemote endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);

    private final String CADN = "CN=CertRevocationStatusCheckTestCA";
    private CA testx509ca;
    private int eeprofileID;
    private String certprofileName;
    private int certprofileID;

    @Before
    public void setUp() throws Exception {
        
        if(!caSession.existsCa(CADN.hashCode())) {
            testx509ca = CaTestUtils.createTestX509CA(CADN, null, false);
            caSession.addCA(alwaysAllowToken, testx509ca);
        }
        final int caid = testx509ca.getCAId();
        
        certprofileName = "CertRevocationStatusCheckerTestCertProfile";
        if (certProfileSession.getCertificateProfile(certprofileName) == null) {
            final CertificateProfile cp = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            List<Integer> availablecas = new ArrayList<Integer>();
            availablecas.add(caid);
            cp.setAvailableCAs(availablecas);
            try {
                certProfileSession.addCertificateProfile(alwaysAllowToken, certprofileName, cp);
            } catch (CertificateProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        certprofileID = certProfileSession.getCertificateProfileId(certprofileName);
        
        final String eepname = "CertRevocationStatusCheckerTestEndEntityProfile";
        if (endEntityProfileSession.getEndEntityProfile(eepname) == null) {
            final EndEntityProfile eep = new EndEntityProfile(true);
            eep.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, ""+certprofileID);
            eep.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, ""+certprofileID);
            eep.setValue(EndEntityProfile.AVAILCAS, 0, ""+caid);
            eep.setValue(EndEntityProfile.DEFAULTCA, 0, ""+caid);
            try {
                endEntityProfileSession.addEndEntityProfile(alwaysAllowToken, eepname, eep);
            } catch (EndEntityProfileExistsException e) {
                e.printStackTrace();
                fail(e.getMessage());
            }
        }
        eeprofileID = endEntityProfileSession.getEndEntityProfileId(eepname);
        
    }
    
    @After
    public void tearDown() throws Exception {
        try {
            // Remove any testca before exiting tests
            Certificate testX509caCert = testx509ca.getCACertificate();
            CryptoTokenTestUtils.removeCryptoToken(null, testx509ca.getCAToken().getCryptoTokenId());
            caSession.removeCA(alwaysAllowToken, testx509ca.getCAId());
            internalCertStoreSession.removeCertificate(testX509caCert);
            certProfileSession.removeCertificateProfile(alwaysAllowToken, certprofileName);
            endEntityProfileSession.removeEndEntityProfile(alwaysAllowToken, "CertRevocationStatusCheckerTestEndEntityProfile");
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
        }

    }

  
    /**
     * 1. Create test certificate
     * 2. Specify a working OCSP URL in the constructor of PKIXCertRevocationStatusChecker
     * 3. Check the revocation status of the test certificate. Expected: certificate not revoked
     * 4. Revoke the test certificate
     * 5. Check the revocation status of the test certificate. Expected: error massage that the certificate is revoked
     */
    @Test
    public void test01VerificationWithOCSPWithStaticUrl() throws Exception {
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        
        String baseUrl = "http://127.0.0.1:8080/ejbca";
        String resourceOcsp = "publicweb/status/ocsp";
        OcspJunitHelper helper = new OcspJunitHelper(baseUrl, resourceOcsp);
        helper.reloadKeys();
        
        ArrayList<X509Certificate> caCertChain = new ArrayList<X509Certificate>();
        caCertChain.add((X509Certificate)testx509ca.getCACertificate());
        
        try {
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
               
            // Check usercert revocation status
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker(baseUrl+"/"+resourceOcsp, null, null, caCertChain);
            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            SingleResp ocspResp1 = checker.getOCSPResponse();
            assertNotNull("The check should have been performed using OCSP, so there should be an OCSP response to fetch", ocspResp1);
            assertNull("The check should have been performed using OCSP, so there should not be CRLs to fetch", checker.getcrl());
            

            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), CADN, 0);
                
            // Check usercert revocation status
            try {
                checker.check(usercert, null);
                fail("The certificate is now revoked and should not have passed the check but it did.");
            } catch (CertPathValidatorException e) { 
                String expectedMsg = "Certificate with serialnumber " + CertTools.getSerialNumberAsString(usercert) + " was revoked";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            SingleResp ocspResp2 = checker.getOCSPResponse();
            assertNotNull("The check should have been performed using OCSP, so there should be an OCSP response to fetch", ocspResp2);
            assertFalse("The OCSP response from the first and second check should not be equals", ocspResp1.equals(ocspResp2));
            assertNull("The check should have been performed using OCSP, so there should not be CRLs to fetch", checker.getcrl());
                
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }
 
    /**
     * 1. Create a test certificate containing AuthorityInformationAccess extension containing an OCSP Locator URL
     * 2. Check the revocation status of the test certificate. Expected: certificate not revoked
     * 3. Revoke the test certificate
     * 4. Check the revocation status of the test certificate. Expected: error massage that the certificate is revoked
     */
    @Test
    public void test02VerificationWithOCSPFromCertExtension() throws Exception {
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        
        String baseUrl = "http://127.0.0.1:8080/ejbca";
        String resourceOcsp = "publicweb/status/ocsp";
        OcspJunitHelper helper = new OcspJunitHelper(baseUrl, resourceOcsp);
        helper.reloadKeys();
        
        try {
            
            CertificateProfile cp = certProfileSession.getCertificateProfile(certprofileID);
            cp.setUseAuthorityInformationAccess(true);
            cp.setOCSPServiceLocatorURI(baseUrl+"/"+resourceOcsp);
            certProfileSession.changeCertificateProfile(alwaysAllowToken, certprofileName, cp);
            
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), eeprofileID, certprofileID);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
               
            
            // Check usercert revocation status
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker((X509Certificate) testx509ca.getCACertificate(), null);
            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            SingleResp ocspResp1 = checker.getOCSPResponse();
            assertNotNull("The check should have been performed using OCSP, so there should be an OCSP response to fetch", ocspResp1);
            assertNull("The check should have been performed using OCSP, so there should not be CRLs to fetch", checker.getcrl());

            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), CADN, 0);
                
            // Check usercert revocation status
            try {
                checker.check(usercert, null);
                fail("The certificate is now revoked and should not have passed the check but it did.");
            } catch (CertPathValidatorException e) { 
                String expectedMsg = "Certificate with serialnumber " + CertTools.getSerialNumberAsString(usercert) + " was revoked";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            SingleResp ocspResp2 = checker.getOCSPResponse();
            assertNotNull("The check should have been performed using OCSP, so there should be an OCSP response to fetch", ocspResp2);
            assertFalse("The OCSP response from the first and second check should not be equals", ocspResp1.equals(ocspResp2));
            assertNull("The check should have been performed using OCSP, so there should not be CRLs to fetch", checker.getcrl());
                
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }

    /**
     * 1. Create a test certificate containing AuthorityInformationAccess extension containing an OCSP Locator URL
     * 2. Create a PKIXCertRevocationStatusChecker object that does not specify an issuer certificate
     * 2. Check the revocation status of the test certificate. Expected: error message that the revocation status could not be checked
     */
    @Test
    public void test03VerificationWithOCSPWithoutCACert() throws Exception {
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        
        try {
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), eeprofileID, certprofileID);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
               
            
            // Check usercert revocation status
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker(null, null);
            try {
                checker.check(usercert, null);
                fail("The check should not have been performed because the input parameters were not satisfactory. Inspite of that, the check was successful.");
            } catch (CertPathValidatorException e) {
                final String expectedMsg = "No issuer CA certificate was found. An issuer CA certificate is needed to create an OCSP request and to get the right CRL";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            assertNull("The check should not have been performed using OCSP, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            assertNull("The check should not have been performed using CRL, so there should not be a CRL to grab", checker.getcrl());

        } finally {
            // Remove it to clean database
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
            internalCertStoreSession.removeCertificate(usercertFp);
        }
    }
    
    /**
     * 1. Create a test certificate containing CRLDistributionPoints extension containing a URL to the right CRL
     * 2. Generate a CRL
     * 3. Check the revocation status of the test certificate. Expected: certificate not revoked
     * 4. Revoke the test certificate
     * 5. Generate a new CRL
     * 6. Check the revocation status of the test certificate. Expected: error massage that the certificate is revoked
     */
    @Test
    public void test04VerificationWithCRLFromCertExtension() throws Exception {

        final String defaultCRLDistPoint = "http://localhost:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=";
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        String crlFp1="", crlFp2="";
        
        try {
            
            
            CertificateProfile cp = certProfileSession.getCertificateProfile(certprofileID);
            cp.setUseCRLDistributionPoint(true);
            cp.setCRLDistributionPointURI(defaultCRLDistPoint+CADN);
            cp.setCRLIssuer(CADN);
            certProfileSession.changeCertificateProfile(alwaysAllowToken, certprofileName, cp);
            
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), eeprofileID, certprofileID);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
            
            
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
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker((X509Certificate) testx509ca.getCACertificate(), null);
            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            CRL crl1 = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be a CRL to grab", crl1);
            
            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), CADN, 0);
            
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
            try {
                checker.check(usercert, null);
                fail("The certificate is now revoked and should not have passed the check but it did.");
            } catch (CertPathValidatorException e) { 
                String expectedMsg = "Certificate with serialnumber " + CertTools.getSerialNumberAsString(usercert) + " was revoked";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            CRL crl2 = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be a CRL to grab", crl2);
            assertFalse("The CRLs from the first and second check should not be the same", crl1.equals(crl2));
            
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp1);
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp2);
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }
  
    /**
     * 1. Create a test certificate
     * 2. Generate a CRL
     * 3. Create a PKIXCertRevocationStatusChecker object specifying a CRL URL
     * 4. Check the revocation status of the test certificate. Expected: certificate not revoked
     * 5. Revoke the test certificate
     * 6. Generate a new CRL
     * 7. Check the revocation status of the test certificate. Expected: error massage that the certificate is revoked
     */
    @Test
    public void test05VerificationWithCRLWithStaticURL() throws Exception {

        X509CAInfo cainfo = (X509CAInfo) testx509ca.getCAInfo();
        final String defaultCRLDistPoint = "http://localhost:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=";
        //http://localhost:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=CN=ManagementCA,O=EJBCA%20Sample,C=SE
        URL crlUrl = new URL(defaultCRLDistPoint + cainfo.getSubjectDN());
        cainfo.setDefaultCRLDistPoint(crlUrl.toString());
        caSession.editCA(alwaysAllowToken, cainfo);
        
        ArrayList<X509Certificate> caCertChain = new ArrayList<X509Certificate>();
        caCertChain.add((X509Certificate)testx509ca.getCACertificate());
        
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        String crlFp1="", crlFp2="";
        
        try {
            
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
            
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
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker(null, cainfo.getDefaultCRLDistPoint(), null, caCertChain);

            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            CRL crl1 = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be a CRL to grab", crl1);
            
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
            try {
                checker.check(usercert, null);
                fail("The certificate is now revoked and should not have passed the check but it did.");
            } catch (CertPathValidatorException e) { 
                String expectedMsg = "Certificate with serialnumber " + CertTools.getSerialNumberAsString(usercert) + " was revoked";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            CRL crl2 = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be a CRL to grab", crl2);
            assertFalse("The CRLs from the first and second check should not be the same", crl1.equals(crl2));
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp1);
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp2);
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }

    /**
     * 1. Create a test certificate containing neither AuthorityInformationAccess not CRLDistributionPoints extensions
     * 2. Create a PKIXCertRevocationStatusChecker object not specifying any URLS
     * 3. Check the revocation status of the test certificate. Expected: error massage that the revocation status could not be checked
     */
    @Test
    public void test06VerificationWithNoLinks() throws Exception {
        
        ArrayList<X509Certificate> caCertChain = new ArrayList<X509Certificate>();
        caCertChain.add((X509Certificate)testx509ca.getCACertificate());
        
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        String crlFp1="";
        
        try {
            
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), SecConst.EMPTY_ENDENTITYPROFILE, CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
            
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
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker("", "", null, caCertChain);

            try {
                checker.check(usercert, null);
                fail("The check should not have been performed because the input parameters were not satisfactory. Inspite of that, the check was successful.");
            } catch (CertPathValidatorException e) {
                final String expectedMsg = "Failed to verify certificate status using the fallback CRL method. Could not find a CRL URL";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            assertNull("The check should not have been performed using OCSP, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            assertNull("The check should not have been performed using CRL, so there should not be a CRL to grab", checker.getcrl());
            
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp1);
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
        }
    }

    @Test
    public void test07VerificationWithMultipleCRLs() throws Exception {

        final String testca2SubjectDN = "CN=SecondTestCA";
        if(caSession.existsCa(testca2SubjectDN)) {
            caSession.removeCA(alwaysAllowToken, testca2SubjectDN.hashCode());
        }
        X509CA testca2 = CaTestUtils.createTestX509CA(testca2SubjectDN, null, false);
        caSession.addCA(alwaysAllowToken, testca2);
        
        final String defaultCRLDistPoint = "http://localhost:8080/ejbca/publicweb/webdist/certdist?cmd=crl&issuer=";
        
        final String username = "CertRevocationStatusCheckTestUser";
        final String userDN = "CN=" + username;
        String usercertFp="";
        String crlFp1="", crlFp2="", testca2CrlFp1="";
        
        try {
            
            
            CertificateProfile cp = certProfileSession.getCertificateProfile(certprofileID);
            cp.setUseCRLDistributionPoint(true);
            cp.setCRLDistributionPointURI(defaultCRLDistPoint+testca2SubjectDN+";"+defaultCRLDistPoint+CADN);
            cp.setCRLIssuer(CADN);
            certProfileSession.changeCertificateProfile(alwaysAllowToken, certprofileName, cp);
            
            // create a user and issue it a certificate
            createUser(username, userDN, testx509ca.getCAId(), eeprofileID, certprofileID);
            final KeyPair userkeys = KeyTools.genKeys("1024", "RSA");
            X509Certificate usercert = (X509Certificate) signSession.createCertificate(alwaysAllowToken, username, "foo123", new PublicKeyWrapper(userkeys.getPublic()));
            usercertFp = CertTools.getFingerprintAsString(usercert);
            
            
            // Generate CRL for the "real" CA
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
            PKIXCertRevocationStatusChecker checker = new PKIXCertRevocationStatusChecker((X509Certificate) testx509ca.getCACertificate(), null);
            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            CRL testx509caCrl = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be at least one CRL to grab", testx509caCrl);
            assertEquals(CADN, CertTools.getIssuerDN((X509CRL)testx509caCrl));
            
            
            // Generate CRL for the second testCA
            revcerts = certStoreSession.listRevokedCertInfo(testca2SubjectDN, -1);
            fullnumber = crlStoreSession.getLastCRLNumber(testca2SubjectDN, false);
            deltanumber = crlStoreSession.getLastCRLNumber(testca2SubjectDN, true);
            // nextCrlNumber: The highest number of last CRL (full or delta) and increased by 1 (both full CRLs and deltaCRLs share the same series of CRL Number)
            nextCrlNumber = ((fullnumber > deltanumber) ? fullnumber : deltanumber) + 1;
            crlCreateSession.generateAndStoreCRL(alwaysAllowToken, testca2, revcerts, -1, nextCrlNumber);
            // We should now have a CRL generated
            crl = crlStoreSession.getLastCRL(testca2SubjectDN, false);
            testca2CrlFp1 = CertTools.getFingerprintAsString(crl);
            
            
            // Check the revocation status again. There should be 2 URL now
            try {
                checker.check(usercert, null);
            } catch (CertPathValidatorException e) {
                fail("The certificate is not revoked and should have passed the check but it did not.");
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            testx509caCrl = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be at least one CRL to grab", testx509caCrl);
            assertEquals(CADN, CertTools.getIssuerDN((X509CRL)testx509caCrl));
            
            
            // Revoke usercert
            eeManagementSession.revokeCert(alwaysAllowToken, CertTools.getSerialNumber(usercert), CADN, 0);
            
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
            try {
                checker.check(usercert, null);
                fail("The certificate is now revoked and should not have passed the check but it did.");
            } catch (CertPathValidatorException e) { 
                String expectedMsg = "Certificate with serialnumber " + CertTools.getSerialNumberAsString(usercert) + " was revoked";
                assertEquals(expectedMsg, e.getLocalizedMessage());
            }
            assertNull("The check was performed using CRL, so there should not be an OCSP response to grab", checker.getOCSPResponse());
            testx509caCrl = checker.getcrl();
            assertNotNull("The check was performed using CRL, so there should be at least one CRL to grab", testx509caCrl);
            assertEquals(CADN, CertTools.getIssuerDN((X509CRL)testx509caCrl));
            
        } finally {
            // Remove it to clean database
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp1);
            internalCertStoreSession.removeCRL(alwaysAllowToken, crlFp2);
            internalCertStoreSession.removeCRL(alwaysAllowToken, testca2CrlFp1);
            internalCertStoreSession.removeCertificate(usercertFp);
            eeManagementSession.revokeAndDeleteUser(alwaysAllowToken, username, ReasonFlags.unused);
            
            caSession.removeCA(alwaysAllowToken, testca2.getCAId());
            internalCertStoreSession.removeCertificate(testca2.getCACertificate());
        }
    }


    
    private void createUser(final String username, final String dn, final int caid, final int eepid, final int cpid)
            throws AuthorizationDeniedException, EndEntityProfileValidationException, WaitingForApprovalException, NoSuchEndEntityException,
            CADoesntExistsException, ApprovalException, CertificateSerialNumberException, IllegalNameException, CustomFieldException {
        final EndEntityInformation user = new EndEntityInformation(username, dn, caid, null, username + "@primekey.se",
                new EndEntityType(EndEntityTypes.ENDUSER), eepid, cpid, SecConst.TOKEN_SOFT_PEM, 0, null);
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

}
