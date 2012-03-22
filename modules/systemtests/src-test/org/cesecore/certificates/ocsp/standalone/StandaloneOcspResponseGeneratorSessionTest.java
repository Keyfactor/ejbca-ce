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
package org.cesecore.certificates.ocsp.standalone;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URL;
import java.security.KeyStore;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Hashtable;
import java.util.List;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
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
import org.bouncycastle.ocsp.SingleResp;
import org.cesecore.CaCreatingTestCase;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.authorization.control.StandardRules;
import org.cesecore.authorization.rules.AccessRuleData;
import org.cesecore.authorization.rules.AccessRuleState;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.configuration.CesecoreConfigurationProxySessionRemote;
import org.cesecore.roles.RoleData;
import org.cesecore.roles.access.RoleAccessSessionRemote;
import org.cesecore.roles.management.RoleManagementSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Functional tests for StandaloneOcspResponseGeneratorSessionBean
 * 
 * @version $Id$
 * 
 */
@Ignore
public class StandaloneOcspResponseGeneratorSessionTest extends CaCreatingTestCase {

    private static final String SIGNATURE_PROVIDER = "BC";
    private static final String P12_DIR = "p12";
    private static final String P12_FILENAME = "ocsp.p12";
    private static final String PASSWORD = "foo123";
    private static final String OCSP_ALIAS = "OCSP Signer";
    private static final String CA_DN = "CN=AdminCA1,O=EJBCA Sample,C=SE";

    private StandaloneOcspResponseGeneratorSessionRemote standaloneOcspResponseGeneratorSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(StandaloneOcspResponseGeneratorSessionRemote.class);
    private RoleManagementSessionRemote roleManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleManagementSessionRemote.class);
    private RoleAccessSessionRemote roleAccessSession = EjbRemoteHelper.INSTANCE.getRemoteSession(RoleAccessSessionRemote.class);
    private InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(InternalCertificateStoreSessionRemote.class);
    private CesecoreConfigurationProxySessionRemote cesecoreConfigurationProxySession = EjbRemoteHelper.INSTANCE
            .getRemoteSession(CesecoreConfigurationProxySessionRemote.class);
    private CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
    private CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);

    private CA x509Ca;
    private X509Certificate caCertificate;
    private X509Certificate p12Certificate;

    @BeforeClass
    public static void setUpCryptoProvider() throws Exception {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setUp() throws Exception {
        final URL url = StandaloneOcspResponseGeneratorSessionTest.class.getResource(P12_DIR);
        String curDir = System.getProperty("user.dir");
        System.out.println(curDir);
        File p12dir = new File(url.getFile());
        // Assert that p12 directory is sane.

        assertTrue(p12dir.exists());
        assertTrue(p12dir.isDirectory());
        assertTrue(p12dir.listFiles().length > 0);
        cesecoreConfigurationProxySession.setConfigurationValue(OcspConfiguration.OCSP_KEYS_DIR, p12dir.getAbsolutePath());

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

        x509Ca = createX509Ca(CA_DN);
        // Remove any lingering testca before starting the tests
        caSession.removeCA(roleMgmgToken, x509Ca.getCAId());
        caSession.addCA(roleMgmgToken, x509Ca);

        caCertificate = (X509Certificate) x509Ca.getCACertificate();

        // Store a root certificate in the database.
        if (certificateStoreSession.findCertificatesBySubject(CA_DN).isEmpty()) {
            certificateStoreSession.storeCertificate(roleMgmgToken, caCertificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ROOTCA, CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "footag", new Date().getTime());
        }

        /* Just to make things easy, dig out the OCSP signer certificate from the pre-manufactured p12 keystore and store it. 
         * It should have the same issuer DN as the ca created above.
         */
        File p12File = new File(p12dir, P12_FILENAME);
        KeyStore keyStore = KeyStore.getInstance("PKCS12", "BC");
        keyStore.load(new FileInputStream(p12File), PASSWORD.toCharArray());

        p12Certificate = (X509Certificate) keyStore.getCertificate(OCSP_ALIAS);

        certificateStoreSession.storeCertificate(roleMgmgToken, p12Certificate, "foo", "1234", CertificateConstants.CERT_ACTIVE,
                CertificateConstants.CERTTYPE_ENDENTITY, CertificateProfileConstants.CERTPROFILE_FIXED_OCSPSIGNER, "footag", new Date().getTime());

        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", CA_DN);
    }

    @After
    public void tearDown() throws Exception {
        try {
            caSession.removeCA(roleMgmgToken, x509Ca.getCAId());
        } finally {
            // Be sure to to this, even if the above fails
            tearDownRemoveRole();
            internalCertificateStoreSession.removeCertificate(caCertificate.getSerialNumber());
            internalCertificateStoreSession.removeCertificate(p12Certificate.getSerialNumber());
        }

        // Restore the default value
        cesecoreConfigurationProxySession.setConfigurationValue("ocsp.defaultresponder", OcspConfiguration.getDefaultResponderId());
    }

    @Test
    public void testStandAloneOcspResponseSanity() throws OCSPException, AuthorizationDeniedException, MalformedRequestException, IOException,
            NoSuchProviderException {

        standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache(PASSWORD);

        // An OCSP request
        OCSPReqGenerator gen = new OCSPReqGenerator();
        gen.addRequest(new CertificateID(CertificateID.HASH_SHA1, caCertificate, p12Certificate.getSerialNumber()));
        Hashtable<ASN1ObjectIdentifier, X509Extension> exts = new Hashtable<ASN1ObjectIdentifier, X509Extension>();
        X509Extension ext = new X509Extension(false, new DEROctetString("123456789".getBytes()));
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, ext);
        gen.setRequestExtensions(new X509Extensions(exts));

        OCSPReq req = gen.generate();
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        // Create the transaction logger for this transaction.
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        // Create the audit logger for this transaction.
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        OcspResponseInformation responseInformation = standaloneOcspResponseGeneratorSession.getOcspResponse(req.getEncoded(),
                null, "", "", null, auditLogger, transactionLogger);
        byte[] responseBytes = responseInformation.getOcspResponse();
        assertNotNull("OCSP resonder replied null", responseBytes);

        OCSPResp response = new OCSPResp(new ByteArrayInputStream(responseBytes));
        assertEquals("Response status not zero.", response.getStatus(), 0);
        BasicOCSPResp basicOcspResponse = (BasicOCSPResp) response.getResponseObject();
        assertTrue("OCSP response was not signed correctly.", basicOcspResponse.verify(p12Certificate.getPublicKey(), SIGNATURE_PROVIDER));
        SingleResp[] singleResponses = basicOcspResponse.getResponses();
        assertEquals("Delivered some thing else than one and exactly one response.", 1, singleResponses.length);
        assertEquals("Response cert did not match up with request cert", p12Certificate.getSerialNumber(), singleResponses[0].getCertID()
                .getSerialNumber());
        assertEquals("Status is not null (good)", null, singleResponses[0].getCertStatus());
    }

}
