/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           *
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.unidfnr.ocsp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.SerializationUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.CaTestUtils;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.CertificateGenerationParams;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.ca.IllegalValidityException;
import org.cesecore.certificates.ca.InvalidAlgorithmException;
import org.cesecore.certificates.ca.SignRequestSignatureException;
import org.cesecore.certificates.ca.X509CAInfo;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.CertificateCreateSessionRemote;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.InternalCertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificate.exception.CustomCertificateSerialNumberException;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessageUtils;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseGeneratorTestSessionRemote;
import org.cesecore.certificates.ocsp.OcspResponseInformation;
import org.cesecore.certificates.ocsp.SHA1DigestCalculator;
import org.cesecore.certificates.ocsp.exception.MalformedRequestException;
import org.cesecore.certificates.ocsp.logging.AuditLogger;
import org.cesecore.certificates.ocsp.logging.GuidHolder;
import org.cesecore.certificates.ocsp.logging.TransactionCounter;
import org.cesecore.certificates.ocsp.logging.TransactionLogger;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenNameInUseException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.mock.authentication.tokens.TestAlwaysAllowLocalAuthenticationToken;
import org.cesecore.util.CertTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.protocol.ocsp.extension.unid.FnrFromUnidExtension;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Functional test of OCSP response generation with UNID-FNR.
 * @version $Id$
 */
public final class UnidFnrOcspTest {

    private static final Logger log = Logger.getLogger(UnidFnrOcspTest.class);

    private static final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
    private static final CertificateCreateSessionRemote certificateCreateSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateCreateSessionRemote.class);
    private static final InternalCertificateStoreSessionRemote internalCertificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalCertificateStoreSessionRemote.class, EjbRemoteHelper.MODULE_TEST);
    private static final OcspResponseGeneratorSessionRemote ocspResponseGeneratorSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspResponseGeneratorSessionRemote.class);
    private static final OcspResponseGeneratorTestSessionRemote ocspResponseGeneratorTestSession = EjbRemoteHelper.INSTANCE.getRemoteSession(OcspResponseGeneratorTestSessionRemote.class, EjbRemoteHelper.MODULE_TEST);

    private static final AuthenticationToken authenticationToken = new TestAlwaysAllowLocalAuthenticationToken(new UsernamePrincipal("Internal Test Admin"));

    private static final BigInteger SERIAL_IN_CERT = new BigInteger("2b77d562b5bfb707", 16);
    private static final String SERIAL_IN_DN = "31129912345-01234";
    private static final String TEST_ROOTCA_NAME = "UnidFnrOcspTestRootCA";
    private static final String TEST_ROOTCA_DN = "CN="+TEST_ROOTCA_NAME+",OU=Test Suite,O=PrimeKey,C=SE";
    private static final String TEST_SUBCA_NAME = "UnidFnrOcspTestSubCA";
    private static final String TEST_SUBCA_DN = "CN="+TEST_SUBCA_NAME+",OU=Test Suite,O=Company A/S,C=NO";
    private static final String TEST_PERSON_DN = "CN=UnidFnrOcspTestPerson1,SN="+SERIAL_IN_DN+",OU=Specimen,C=NO";

    private static final byte[] personCertCsr = ("-----BEGIN CERTIFICATE REQUEST-----\n" +
        "MIIC0zCCAbsCAQAwgY0xCzAJBgNVBAYTAk5PMREwDwYDVQQIDAhGaW5ubWFyazEU\n" +
        "MBIGA1UECgwLQ29tcGFueSBBL1MxETAPBgNVBAsMCFNwZWNpbWVuMUIwQAYDVQQD\n" +
        "DDlUZXN0IENTUi4gQWxsIHRoaXMgaW5mb3JtYXRpb24gc2hvdWxkIGJlIGlnbm9y\n" +
        "ZWQgYnkgRUpCQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC89wHs\n" +
        "ESX6ZjMZN2qr9oKKGMrUC4nriMikOMvfpdi+kWLPGpggOoGWnbWD62pHfQIi3BAR\n" +
        "cCficpXLYHOt8LHF/Dcvyoyc2s+8+8moaBP2tilBqXGJ4ERm4NMzLUWIGcz+vz5A\n" +
        "na0mrJcwHqqxxp7DE5uJZl+ha7z8JUfzPwd3rgSSfWGjKvYz+jRdykGSTDUd7q9x\n" +
        "UN7o3FokvhpE66llOBYOoSDLjbbgnyoc8pJAez3Bhot+179q6LQy6kKZv0RkrBlN\n" +
        "BNxhg1J23HqIIpT2Ibcm8LKVkopJmpioiKl+jhtqmMc9Zy1fazYau8RyKg4boJAo\n" +
        "ONl82r097JoKzB65AgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAHmym8PxKpExc\n" +
        "m6rn1ZsgAEk2z/TY0VSGCku944QjDdzntpmkHfZGpuTA6Yvy0BCW638s8igrcKNY\n" +
        "5q1E68Y5aCoyUHsozWpyEME7YiI0IyRkSF8IJYzSeXszlQCTeoZ6IaqX3yId96JY\n" +
        "S5Z459U9haKbHUzude5xDAxSqjQz8JUGTcBMtfAukFt85fdjNrMl4jeidyBEFv1t\n" +
        "2mgPGR/2CZ4Uzh5CFj2baAIGDOYlyf2Git0j19YTunVbbYdzC9bIzuPEJUphaoe6\n" +
        "QPFEQr0KBZRdW2V0oiz6EmKNxtF/llKc0Osade214+pdy5zU9r9qsj+NLYWEK3BS\n" +
        "qfy6/xzFGg==\n" +
        "-----END CERTIFICATE REQUEST-----").getBytes(StandardCharsets.US_ASCII);

    private static X509CAInfo rootCA;
    private static X509CAInfo subCA;
    private static X509Certificate personCert;

    @BeforeClass
    public static void setup() throws AuthorizationDeniedException, InvalidKeyException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, CryptoTokenNameInUseException, InvalidAlgorithmParameterException, CertificateException, InvalidAlgorithmException, IllegalStateException, OperatorCreationException, CAExistsException, CustomCertificateSerialNumberException, IllegalKeyException, CADoesntExistsException, CertificateCreateException, SignRequestSignatureException, IllegalNameException, CertificateRevokeException, CertificateSerialNumberException, IllegalValidityException, CAOfflineException, CertificateExtensionException {
        cleanup();
        log.trace(">setup");
        // Create CAs
        rootCA = (X509CAInfo)CaTestUtils.createX509Ca(authenticationToken, TEST_ROOTCA_NAME, TEST_ROOTCA_NAME, TEST_ROOTCA_DN).getCAInfo();
        subCA = (X509CAInfo)CaTestUtils.createTestX509SubCAGenKeys(authenticationToken, TEST_SUBCA_DN, "foo123".toCharArray(), rootCA.getCAId(), "1024");
        assertEquals(TEST_ROOTCA_DN, CertTools.getIssuerDN(rootCA.getCertificateChain().get(0))); // assert it was created as a Root CA
        assertEquals(TEST_ROOTCA_DN, CertTools.getIssuerDN(subCA.getCertificateChain().get(0))); // assert it was created as a Sub CA
        SerializationUtils.clone(subCA.getCertificateChain().get(0)); // assert that the Sub CA certificate can be (de-)serialized, as it will be sent over Remote EJB in the test
        // Create End Entity
        final EndEntityInformation eei = new EndEntityInformation();
        eei.setType(EndEntityTypes.ENDUSER.toEndEntityType());
        eei.setEndEntityProfileId(EndEntityConstants.EMPTY_END_ENTITY_PROFILE);
        eei.setCertificateProfileId(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        eei.setDN(TEST_PERSON_DN);
        eei.setCAId(subCA.getCAId());
        final PKCS10RequestMessage req = RequestMessageUtils.genPKCS10RequestMessage(personCertCsr);
        assertNotNull("Failed to parse test CSR. Should never happen.", req);
        final CertificateResponseMessage resp = certificateCreateSession.createCertificate(authenticationToken, eei, req, X509ResponseMessage.class, new CertificateGenerationParams());
        personCert = (X509Certificate) resp.getCertificate();
        // Enable UNID-FNR
        // TODO dynamically enable UNID-FNR
        // TODO check for presence of UNID-FNR datasource and insert into table? or mock it?
        // Reload
        ocspResponseGeneratorTestSession.reloadOcspSigningCache();
        log.trace("<setup");
    }
    
    @AfterClass
    public static void cleanup() throws AuthorizationDeniedException {
        log.trace("<cleanup");
        internalCertificateStoreSession.removeCertificatesBySubject(TEST_PERSON_DN);
        CaTestUtils.removeCa(authenticationToken, TEST_SUBCA_NAME, TEST_SUBCA_NAME);
        CaTestUtils.removeCa(authenticationToken, TEST_ROOTCA_NAME, TEST_ROOTCA_NAME);
        // Avoid memory leak (static variables)
        subCA = null;
        rootCA = null;
        personCert = null;
        log.trace("<cleanup");
    }
    
    @Test
    public void testGenerateResponse() throws MalformedRequestException, OCSPException, IOException, CertificateEncodingException {
        log.trace(">testGenerateResponse");
        final int localTransactionId = TransactionCounter.INSTANCE.getTransactionNumber();
        TransactionLogger transactionLogger = new TransactionLogger(localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");
        AuditLogger auditLogger = new AuditLogger("", localTransactionId, GuidHolder.INSTANCE.getGlobalUid(), "");

        final X509Certificate caCertificate = (X509Certificate) subCA.getCertificateChain().get(0);
        assertNotNull(caCertificate);

        OCSPReqBuilder gen = new OCSPReqBuilder();
        gen.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, SERIAL_IN_CERT));
        Extension[] extensions = new Extension[2];
        extensions[0] = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, false, new DEROctetString("987654321098765".getBytes()));
        extensions[1] = new Extension(FnrFromUnidExtension.FnrFromUnidOid, false, new DEROctetString(new FnrFromUnidExtension("1")));
        gen.setRequestExtensions(new Extensions(extensions));
        OCSPReq req = gen.build();
        assertNotNull(req);

        // Send an OCSP request without a client certificate. Should not result in any UNID-FNR extension being sent back
        OcspResponseInformation ocspResponse = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), null, "", null, null, auditLogger, transactionLogger);
        assertNotNull("Response shouldn't be null", ocspResponse);
        byte[] responseBytes = ocspResponse.getOcspResponse();
        BasicOCSPResp basicResponse = (BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject();
        assertNotNull("basicResponse should not be null", basicResponse);
        assertEquals("OCSP response should contain one extension only (nonce extension)", 1, basicResponse.getExtensionOIDs().size());
        assertEquals("Only extension should be id_pkix_ocsp_nonce.", OCSPObjectIdentifiers.id_pkix_ocsp_nonce, basicResponse.getExtensionOIDs().get(0));

        // Send an OCSP request with a (mock) client certificate. This should result in a UNID-FNR extension being sent back
        X509Certificate[] mockClientCerts = new X509Certificate[1];
        mockClientCerts[0] = personCert;
        responseBytes = ocspResponseGeneratorSession.getOcspResponse(req.getEncoded(), mockClientCerts, "", null, null, auditLogger, transactionLogger).getOcspResponse();
        basicResponse = (BasicOCSPResp) (new OCSPResp(responseBytes)).getResponseObject();
        // TODO

        log.trace("<testGenerateResponse");
    }

}
