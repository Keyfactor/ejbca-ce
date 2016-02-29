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
package org.ejbca.ui.web;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.ca.CA;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionLocal;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.request.ResponseMessage;
import org.cesecore.certificates.certificate.request.X509ResponseMessage;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.easymock.EasyMock;
import org.ejbca.core.ejb.ca.sign.SignSessionLocal;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 *
 */
public class RequestHelperTest {
    
    /*
     * CSR for a external CA with DN: CN=foos
     */
    private static final byte[] PRE_GENERATED_CSR = new byte[] { 45, 45, 45, 45, 45, 66, 69, 71, 73, 78, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84,
            69, 32, 82, 69, 81, 85, 69, 83, 84, 45, 45, 45, 45, 45, 10, 77, 73, 73, 67, 86, 68, 67, 67, 65, 84, 119, 67, 65, 81, 65, 119, 68, 122,
            69, 78, 77, 65, 115, 71, 65, 49, 85, 69, 65, 119, 119, 69, 90, 109, 57, 118, 99, 122, 67, 67, 65, 83, 73, 119, 68, 81, 89, 74, 75, 111,
            90, 73, 104, 118, 99, 78, 65, 81, 69, 66, 66, 81, 65, 68, 10, 103, 103, 69, 80, 65, 68, 67, 67, 65, 81, 111, 67, 103, 103, 69, 66, 65,
            78, 119, 103, 65, 87, 69, 90, 101, 107, 51, 49, 120, 83, 72, 103, 68, 111, 66, 121, 122, 83, 104, 107, 54, 98, 79, 78, 84, 73, 71, 75,
            78, 50, 118, 110, 50, 56, 70, 55, 87, 79, 121, 84, 77, 56, 53, 90, 10, 55, 107, 67, 70, 86, 108, 103, 87, 74, 101, 106, 112, 117, 67, 88,
            74, 72, 82, 111, 77, 110, 122, 107, 122, 108, 90, 78, 109, 65, 66, 52, 103, 70, 101, 66, 67, 105, 99, 109, 49, 48, 100, 110, 51, 79, 47,
            47, 101, 100, 73, 47, 74, 47, 52, 72, 109, 85, 86, 81, 66, 67, 109, 108, 111, 10, 99, 48, 65, 50, 116, 53, 78, 77, 98, 111, 114, 98, 100,
            51, 81, 89, 68, 51, 106, 48, 88, 48, 102, 119, 117, 86, 49, 43, 112, 121, 119, 112, 108, 72, 65, 53, 107, 97, 82, 51, 118, 112, 109, 89,
            115, 121, 48, 110, 51, 71, 118, 79, 105, 118, 100, 121, 65, 122, 90, 90, 97, 52, 109, 51, 10, 87, 100, 55, 52, 83, 120, 113, 79, 73, 101,
            76, 80, 97, 83, 55, 54, 78, 51, 120, 70, 115, 76, 49, 52, 48, 105, 77, 47, 90, 115, 47, 79, 115, 106, 74, 88, 112, 82, 105, 115, 115, 69,
            79, 53, 110, 43, 86, 90, 66, 69, 112, 90, 119, 84, 103, 113, 118, 68, 74, 50, 53, 66, 105, 110, 10, 113, 81, 43, 66, 75, 102, 65, 88, 89,
            99, 89, 101, 84, 100, 89, 98, 70, 83, 108, 115, 81, 67, 66, 102, 90, 105, 89, 73, 118, 75, 76, 118, 116, 47, 100, 55, 90, 52, 66, 43, 67,
            122, 87, 70, 89, 67, 111, 112, 117, 111, 65, 108, 112, 110, 88, 52, 113, 90, 74, 56, 73, 57, 120, 100, 10, 73, 74, 122, 97, 70, 78, 88,
            115, 78, 84, 49, 113, 68, 102, 104, 81, 111, 73, 116, 77, 78, 43, 57, 89, 66, 83, 79, 119, 112, 81, 110, 107, 115, 52, 70, 98, 114, 77,
            115, 67, 65, 119, 69, 65, 65, 97, 65, 65, 77, 65, 48, 71, 67, 83, 113, 71, 83, 73, 98, 51, 68, 81, 69, 66, 10, 66, 81, 85, 65, 65, 52,
            73, 66, 65, 81, 67, 50, 105, 69, 88, 51, 72, 89, 114, 107, 71, 47, 87, 73, 71, 90, 73, 88, 87, 104, 108, 120, 103, 67, 106, 98, 51, 68,
            47, 49, 68, 107, 113, 69, 103, 121, 77, 85, 105, 82, 98, 121, 79, 89, 87, 99, 51, 53, 107, 100, 117, 89, 90, 109, 10, 70, 51, 88, 66, 54,
            70, 52, 106, 81, 70, 120, 105, 56, 103, 111, 119, 116, 81, 89, 115, 52, 74, 118, 112, 52, 116, 85, 109, 82, 116, 115, 52, 122, 67, 82,
            65, 119, 75, 65, 99, 107, 99, 89, 113, 74, 87, 114, 69, 43, 57, 65, 118, 102, 99, 57, 57, 67, 84, 71, 97, 80, 119, 78, 106, 10, 104, 52,
            120, 105, 68, 85, 88, 68, 115, 89, 49, 105, 100, 102, 51, 76, 57, 102, 114, 120, 79, 89, 69, 83, 100, 73, 108, 100, 105, 79, 115, 80, 73,
            86, 87, 79, 98, 73, 83, 105, 102, 69, 109, 120, 53, 110, 55, 119, 87, 88, 67, 56, 66, 50, 55, 122, 82, 71, 117, 65, 88, 52, 49, 43, 10,
            65, 74, 69, 51, 48, 73, 87, 111, 57, 79, 47, 57, 49, 43, 105, 117, 99, 51, 90, 85, 50, 71, 53, 83, 77, 100, 86, 43, 78, 79, 47, 102, 116,
            107, 86, 85, 49, 108, 81, 70, 67, 52, 76, 98, 74, 80, 82, 106, 88, 76, 89, 106, 103, 54, 51, 57, 43, 101, 114, 53, 103, 97, 108, 49, 10,
            112, 73, 74, 120, 117, 71, 50, 48, 74, 55, 79, 54, 88, 49, 77, 67, 57, 56, 108, 80, 83, 111, 89, 50, 83, 104, 111, 121, 76, 109, 101, 66,
            117, 80, 81, 48, 90, 56, 56, 68, 107, 53, 99, 116, 77, 110, 80, 57, 122, 109, 86, 73, 80, 72, 81, 69, 82, 103, 74, 112, 55, 114, 72, 113,
            10, 101, 83, 116, 75, 102, 74, 86, 105, 88, 119, 53, 112, 108, 117, 98, 74, 119, 78, 69, 77, 43, 122, 104, 77, 88, 52, 100, 49, 70, 43,
            90, 116, 10, 45, 45, 45, 45, 45, 69, 78, 68, 32, 67, 69, 82, 84, 73, 70, 73, 67, 65, 84, 69, 32, 82, 69, 81, 85, 69, 83, 84, 45, 45, 45,
            45, 45, 10 };

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @SuppressWarnings("unchecked")
    @Test
    public void testPkcs10CertRequestWithCertificateChain() throws Exception {
        RequestHelper requestHelper = new RequestHelper(null, null);

        //Generate a self signed certificate to act as a CA cert, and a signed certificate.
        KeyPair caKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        Certificate caCert = CertTools.genSelfCert("CN=foo", 365, null, caKeys.getPrivate(), caKeys.getPublic(),
                AlgorithmConstants.SIGALG_SHA1_WITH_RSA, false);
        KeyPair replyKeys = KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA);
        final SubjectPublicKeyInfo pkinfo = SubjectPublicKeyInfo.getInstance((ASN1Sequence) ASN1Primitive.fromByteArray(replyKeys.getPublic().getEncoded()));
        String signedCertDn = "CN=signedcert";
        byte[] serno = new byte[8];
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(new Date().getTime());
        random.nextBytes(serno);
        Date firstDate = new Date();
        // Set back startdate ten minutes to avoid some problems with wrongly set clocks.
        firstDate.setTime(firstDate.getTime() - (10 * 60 * 1000));
        Date lastDate = new Date();
        // validity in days = validity*24*60*60*1000 milliseconds
        lastDate.setTime(lastDate.getTime() + (24 * 60 * 60 * 1000));
        X509v3CertificateBuilder certbuilder = new X509v3CertificateBuilder(CertTools.stringToBcX500Name("CN=foo"),
                new java.math.BigInteger(serno).abs(), firstDate, lastDate, CertTools.stringToBcX500Name(signedCertDn), pkinfo);
        final ContentSigner signer = new BufferingContentSigner(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA1_WITH_RSA).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caKeys
                .getPrivate()), 20480);
        final X509CertificateHolder certHolder = certbuilder.build(signer);
        final X509Certificate signedCert = CertTools.getCertfromByteArray(certHolder.getEncoded(), X509Certificate.class);

        //Setup mocks
        SignSessionLocal signsession = EasyMock.createMock(SignSessionLocal.class);
        ResponseMessage responseMessage = EasyMock.createMock(X509ResponseMessage.class);
        //EasyMock.expect(signsession.createCertificate(authenticationToken, EasyMock.anyObject(RequestMessage.class), X509ResponseMessage.class, null)).andReturn(responseMessage);
        EasyMock.expect(
                signsession.createCertificate(EasyMock.anyObject(AuthenticationToken.class), EasyMock.anyObject(RequestMessage.class),
                        EasyMock.anyObject(X509ResponseMessage.class.getClass()), EasyMock.anyObject(EndEntityInformation.class))).andReturn(
                responseMessage);
        EasyMock.expect(responseMessage.getResponseMessage()).andReturn(signedCert.getEncoded());
        CaSessionLocal caSession = EasyMock.createMock(CaSessionLocal.class);
        CA ca = EasyMock.createMock(CA.class);
        EasyMock.expect(signsession.getCAFromRequest(EasyMock.anyObject(AuthenticationToken.class), EasyMock.anyObject(RequestMessage.class),
                EasyMock.anyBoolean())).andReturn(ca);
        CAInfo caInfo = EasyMock.createMock(CAInfo.class);
        EasyMock.expect(ca.getCAInfo()).andReturn(caInfo);
        EasyMock.expect(caInfo.getCertificateChain()).andReturn(Arrays.asList(caCert));
        EasyMock.replay(caInfo, ca, responseMessage, signsession, caSession);

        //Perform test
        byte[] result = requestHelper.pkcs10CertRequest(signsession, caSession, PRE_GENERATED_CSR, "foo", "foo123", CertificateResponseType.ENCODED_CERTIFICATE_CHAIN).getEncoded();
        List<Certificate> certChain =  CertTools.getCertsFromPEM(new ByteArrayInputStream(result), Certificate.class);
        assertEquals(signedCert, certChain.get(0));
        assertEquals(caCert, certChain.get(1));
        
        //Verify that mocks have behaved as planned
        EasyMock.verify(caInfo, ca, responseMessage, signsession, caSession);
    }
}
