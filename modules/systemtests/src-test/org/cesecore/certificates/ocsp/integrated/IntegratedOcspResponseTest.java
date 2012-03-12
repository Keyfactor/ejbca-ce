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
package org.cesecore.certificates.ocsp.integrated;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import javax.ejb.EJBException;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.ocsp.BasicOCSPResp;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.ocsp.OCSPReq;
import org.bouncycastle.ocsp.OCSPReqGenerator;
import org.bouncycastle.ocsp.OCSPResp;
import org.bouncycastle.ocsp.RevokedStatus;
import org.bouncycastle.ocsp.SingleResp;
import org.bouncycastle.ocsp.UnknownStatus;
import org.cesecore.CaCreatingTestCase;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.request.SimpleRequestMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.exception.OcspFailureException;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.RoleNotFoundException;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * 
 * Based on OcspUtilTest.java 9435 2010-07-14 15:18:39Z mikekushner
 * 
 * @version $Id: IntegratedOcspResponseTest.java 1308 2012-02-17 10:03:38Z mikek $
 * 
 */
public class IntegratedOcspResponseTest extends CaCreatingTestCase {

    private static final String SIGNATURE_PROVIDER = "BC";
    private static final String DN = "C=SE,O=Test,CN=TEST";

    private IntegratedOcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(IntegratedOcspResponseGeneratorSessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class);

    private CA testx509ca;

    private X509Certificate caCertificate;
    private X509Certificate ocspCertificate;

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        
        // Set up base role that can edit roles
        setUpAuthTokenAndRole("OcspSessionTest");

        // Now we have a role that can edit roles, we can edit this role to include more privileges
        RoleData role = roleAccessSession.findRole("OcspSessionTest");

        // Add rules to the role
        List<AccessRuleData> accessRules = new ArrayList<AccessRuleData>();
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAADD.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAEDIT.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAREMOVE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESSBASE.resource(), AccessRuleState.RULE_ACCEPT, true));
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CREATECERT.resource(), AccessRuleState.RULE_ACCEPT, true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        testx509ca = createX509Ca("CN=TEST,O=Test,C=SE");
        accessRules.add(new AccessRuleData(role.getRoleName(), StandardRules.CAACCESS.resource() + testx509ca.getCAId(), AccessRuleState.RULE_ACCEPT,
                true));
        roleManagementSession.addAccessRulesToRole(roleMgmgToken, role, accessRules);

        // Remove any lingering testca before starting the tests
        caSession.removeCA(roleMgmgToken, testx509ca.getCAId());

        caSession.addCA(roleMgmgToken, testx509ca);

        caCertificate = (X509Certificate) testx509ca.getCACertificate();

        // Store a root certificate in the database.
        if (certificateStoreSession.findCertificatesBySubject(DN).isEmpty()) {
            certificateStoreSession.storeCertificate(roleMgmgToken, caCertificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
        }

        EndEntityInformation user = new EndEntityInformation("username", "CN=User", testx509ca.getCAId(), "rfc822Name=user@user.com",
                "user@user.com", EndEntityTypes.ENDUSER.toEndEntityType(), 0, 0, EndEntityConstants.TOKEN_USERGEN, 0, null);
        user.setPassword("foo123");
        KeyPair keys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        SimpleRequestMessage req = new SimpleRequestMessage(keys.getPublic(), user.getUsername(), user.getPassword());

        ocspCertificate = (X509Certificate) (((X509ResponseMessage) certificateCreateSession.createCertificate(roleMgmgToken, user, req,
                X509ResponseMessage.class)).getCertificate());

        // Modify the default value
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", "CN=TEST,O=Test,C=SE");
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");

    }

    @After
    public void tearDown() throws AuthorizationDeniedException, RoleNotFoundException {
        try {
            caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
            internalCertificateStoreSession.removeCertificate(caCertificate.getSerialNumber());
            internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        }

        // Restore the default value
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", OcspConfiguration.getDefaultResponderId());
    }

    /**
     * Tests creating an OCSP response using the root CA cert.
     */
    @Test
    public void testGetOcspResponseSanity() throws Exception {

        testx509ca.getCAToken().getCryptoToken();

        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);
        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, caCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", caCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    @Test
    public void testGetOcspResponseWithOcspCertificate() throws Exception {
        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, ocspCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

    @Test
    public void testGetOcspResponseWithRevokedCertificate() throws Exception {
        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, ocspCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        // Now revoke the ocspCertificate
        certificateStoreSession.setRevokeStatus(roleMgmgToken, ocspCertificate, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED, null);

        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        Object status = singleResponses[0].getCertStatus();
        assertTrue("Status is not RevokedStatus", status instanceof RevokedStatus);
        RevokedStatus rev = (RevokedStatus) status;
        assertTrue("Status does not have reason", rev.hasRevocationReason());
        int reason = rev.getRevocationReason();
        assertEquals("Wrong revocation reason", reason, RevokedCertInfo.REVOCATION_REASON_UNSPECIFIED);
    }

    @Test
    public void testGetOcspResponseWithUnavailableCertificate() throws Exception {
        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, ocspCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        // Now remove the certificate
        internalCertificateStoreSession.removeCertificate(ocspCertificate.getSerialNumber());
        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        // Set that an unknown CA is "good", and redo the test.
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "true");

        responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        // Assert that status is null, i.e. "good"
        assertNull(singleResponses[0].getCertStatus());

        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.nonexistingisgood", "false");
    }

    /**
     * Note that this test is time dependent. Debugging it will create strange behavior.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws MalformedRequestException
     * @throws IOException
     * @throws InterruptedException
     * @throws IllegalCryptoTokenException
     * @throws CADoesntExistsException
     */
    @Test
    public void testCacheUpdates() throws OCSPException, AuthorizationDeniedException, MalformedRequestException, IOException, InterruptedException,
            CADoesntExistsException, IllegalCryptoTokenException {
        final Integer timeToWait = 2;
        // Set the validity time to a single second for testing purposes.
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.signtrustvalidtime", timeToWait.toString());

        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        try {

            // An OCSP request
            OCSPReqGenerator gen = new OCSPReqGenerator();
            gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, ocspCertificate.getSerialNumber()));
            Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
            X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
            exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
            gen.setRequestExtensions(new X509Extensions(exts));

            OCSPReq req = gen.generate();

            byte[] responseBytes;

            ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
            assertNotNull("OCSP resonder replied null", responseBytes);
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because initial ocsp response failed.", ((BasicOCSPResp) (new OCSPResp(new ByteArrayInputStream(
                    responseBytes))).getResponseObject()).getResponses()[0].getCertStatus());
            // Erase the cert. It should still exist in the cache.
            caSession.removeCA(roleMgmgToken, testx509ca.getCAId());
            responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
            // Initial assert that status is null, i.e. "good"
            assertNull("Test could not run because cache changed before the entire test could run.", ((BasicOCSPResp) (new OCSPResp(
                    new ByteArrayInputStream(responseBytes))).getResponseObject()).getResponses()[0].getCertStatus());

            // Now sleep and try again, Glassfish has a default "minimum-delivery-interval-in-millis" of 7 seconds, so we have
            // to wait that long, make it 8 seconds. We have set the timer to 2 seconds above.
            Thread.sleep(8 * 1000);

            // Since the CA is gone, expect an exception here.
            try {
                ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
                assertTrue("Should throw OcspException", false);
            } catch (OcspFailureException e) {
                // In JBoss this works, the client actually gets an OcspException
                assertEquals("Unable to find CA certificate and key to generate OCSP response.", e.getMessage());
            } catch (EJBException e) {
                // In glassfish, a RuntimeException causes an EJBException to be thrown, wrapping the OcspException in many layers...
                Throwable e1 = e.getCausedByException();
                Throwable e2 = e1.getCause();
                Throwable e3 = e2.getCause();
                assertTrue(e3 instanceof OcspFailureException);
                OcspFailureException e4 = (OcspFailureException) e3;
                assertEquals("Unable to find CA certificate and key to generate OCSP response.", e4.getMessage());
            }

        } finally {
            // Reset sign trust valid time.
            cesecoreConfigurationProxySession.setConfigurationValue("ocsp.signtrustvalidtime",
                    Integer.toString(OcspConfiguration.getSigningCertsValidTime()));

        }
    }

    /**
     * This test should use the default OCSP responder to sign the response as unknown.
     * 
     * @throws OCSPException
     * @throws AuthorizationDeniedException
     * @throws IOException
     * @throws MalformedRequestException
     * @throws CADoesntExistsException
     * @throws IllegalCryptoTokenException
     * @throws NoSuchProviderException
     */
    @Test
    public void testGetOcspResponseWithCertificateFromUnknownCa() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException, NoSuchProviderException {

        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, ocspCertificate, ocspCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        byte[] responseBytes = ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(caCertificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();

        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", ocspCertificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());

        assertTrue(singleResponses[0].getCertStatus() instanceof UnknownStatus);

    }

    @Test
    public void testGetOcspResponseWithIncorrectDefaultResponder() throws OCSPException, AuthorizationDeniedException, IOException,
            MalformedRequestException, CADoesntExistsException, IllegalCryptoTokenException {
        // Restore the default value
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", "CN=FancyPants");

        ocspResponseGeneratorSession.reloadTokenAndChainCache(roleMgmgToken);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, ocspCertificate, ocspCertificate.getSerialNumber()));
        Hashtable<DERObjectIdentifier, X509Extension> exts = new Hashtable<DERObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();

        // At first try, it should throw an exception because it can not find the default responder
        try {
            ocspResponseGeneratorSession.getOcspResponse(roleMgmgToken, req.getEncoded(), null, "", "");
            fail("Should throw OcspFailureException");
        } catch (OcspFailureException e) {
            // In JBoss this works, the client actually gets an OcspException
            assertEquals("Unable to find CA certificate and key to generate OCSP response.", e.getMessage());
        } catch (EJBException e) {
            // In glassfish, a RuntimeException causes an EJBException to be thrown, wrapping the OcspException in many layers...
            Throwable e1 = e.getCausedByException();
            Throwable e2 = e1.getCause();
            Throwable e3 = e2.getCause();
            assertTrue(e3 instanceof OcspFailureException);
            OcspFailureException e4 = (OcspFailureException) e3;
            assertEquals("Unable to find CA certificate and key to generate OCSP response.", e4.getMessage());
        }

    }


}
