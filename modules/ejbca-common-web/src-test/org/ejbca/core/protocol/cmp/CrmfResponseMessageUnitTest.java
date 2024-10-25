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

package org.ejbca.core.protocol.cmp;

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
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.certificate.SimpleCertGenerator;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.EncryptedKey;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOPrivKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.crmf.SubsequentMessage;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRepMessage;
import org.bouncycastle.cert.crmf.CertificateResponse;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.jcajce.JceKEMEnvelopedRecipient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.cesecore.certificates.certificate.request.CertificateResponseMessage;
import org.cesecore.certificates.certificate.request.ResponseMessageUtils;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Test to verify that CrmfResponseMessage can be properly created.
 */
public class CrmfResponseMessageUnitTest {

    private static KeyPair caKeysMLDSA;
    private static KeyPair eeKeysMLKEM;
    private static KeyPair eeKeysMLDSA;
    private static KeyPair eeKeysEC;
    private static KeyPair eeKeysRSA;
    private static X509Certificate cacert;
    private static X509Certificate eecertMLKEM;
    private static X509Certificate eecertMLDSA;
    private static X509Certificate eecertEC;
    private static X509Certificate eecertRSA;

    /** Things we only want to do once
     * @throws CertIOException
     * @throws OperatorCreationException
     * @throws CertificateParsingException
     * @throws InvalidAlgorithmParameterException */
    @BeforeClass
    public static void beforeClass() throws CertificateParsingException, OperatorCreationException, CertIOException, InvalidAlgorithmParameterException {
        CryptoProviderTools.installBCProviderIfNotAvailable();

        // First step for the client - we generate a key pair
        caKeysMLDSA = KeyTools.genKeys(AlgorithmConstants.KEYALGORITHM_MLDSA44, AlgorithmConstants.KEYALGORITHM_MLDSA44);
        eeKeysMLKEM = KeyTools.genKeys(AlgorithmConstants.KEYALGORITHM_MLKEM512, AlgorithmConstants.KEYALGORITHM_MLKEM512);
        eeKeysMLDSA = KeyTools.genKeys(AlgorithmConstants.KEYALGORITHM_MLDSA44, AlgorithmConstants.KEYALGORITHM_MLDSA44);
        eeKeysEC = KeyTools.genKeys("secp256r1", AlgorithmConstants.KEYALGORITHM_EC);
        eeKeysRSA = KeyTools.genKeys("1024", AlgorithmConstants.KEYALGORITHM_RSA);

        // A bogus CA
        SimpleCertGenerator caGen = SimpleCertGenerator.forTESTCaCert();
        caGen.setIssuerPrivKey(caKeysMLDSA.getPrivate());
        caGen.setEntityPubKey(caKeysMLDSA.getPublic());
        caGen.setSignatureAlgorithm(AlgorithmConstants.SIGALG_MLDSA44);
        cacert = caGen.generateCertificate();
        // A bogus end entity with ML-KEM keys
        {
            SimpleCertGenerator eeGen = SimpleCertGenerator.forTESTLeafCert();
            eeGen.setSubjectDn("CN=testCMPResponseMessage");
            eeGen.setIssuerPrivKey(caKeysMLDSA.getPrivate());
            eeGen.setSignatureAlgorithm(AlgorithmConstants.SIGALG_MLDSA44);
            eeGen.setEntityPubKey(eeKeysMLKEM.getPublic());
            eecertMLKEM = eeGen.generateCertificate();
        }
        // A bogus end entity with ML-DSA keys
        {
            SimpleCertGenerator eeGen = SimpleCertGenerator.forTESTLeafCert();
            eeGen.setSubjectDn("CN=testCMPResponseMessage");
            eeGen.setIssuerPrivKey(caKeysMLDSA.getPrivate());
            eeGen.setSignatureAlgorithm(AlgorithmConstants.SIGALG_MLDSA44);
            eeGen.setEntityPubKey(eeKeysMLDSA.getPublic());
            eecertMLDSA = eeGen.generateCertificate();
        }
        // A bogus end entity with EC keys
        {
            SimpleCertGenerator eeGen = SimpleCertGenerator.forTESTLeafCert();
            eeGen.setSubjectDn("CN=testCMPResponseMessage");
            eeGen.setIssuerPrivKey(caKeysMLDSA.getPrivate());
            eeGen.setSignatureAlgorithm(AlgorithmConstants.SIGALG_MLDSA44);
            eeGen.setEntityPubKey(eeKeysEC.getPublic());
            eecertEC = eeGen.generateCertificate();
        }
        // A bogus end entity with ML-DSA keys
        {
            SimpleCertGenerator eeGen = SimpleCertGenerator.forTESTLeafCert();
            eeGen.setSubjectDn("CN=testCMPResponseMessage");
            eeGen.setIssuerPrivKey(caKeysMLDSA.getPrivate());
            eeGen.setSignatureAlgorithm(AlgorithmConstants.SIGALG_MLDSA44);
            eeGen.setEntityPubKey(eeKeysRSA.getPublic());
            eecertRSA = eeGen.generateCertificate();
        }
    }

    @Before
    public void setUp() throws Exception {
    }

    @Test
    public void testCMPResponseMessageSerialization() throws InvalidAlgorithmParameterException, CertificateParsingException, OperatorCreationException, IOException, ClassNotFoundException, InvalidKeyException, CertificateEncodingException, NoSuchAlgorithmException, NoSuchProviderException, CRLException {

        // Create a PKIMessage
        PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2000, eeKeysMLKEM, cacert.getIssuerX500Principal().getName(), eecertMLKEM.getSubjectX500Principal().getName(),
                new ProofOfPossession() // RaVerifiedPOP
                );
        CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");

        List<Certificate> cachain = Arrays.asList(cacert);
        CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull("Should manage to create a response message", resp);
        resp.setCertificate(eecertMLKEM);
        resp.setCACert(cacert);
        resp.create();

        // Serialize it
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(resp);
        // Deserialize it
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(baos.toByteArray()));
        Object o = ois.readObject();
        assertTrue("The deserialized object was not of type CertificateResponseMessage.", o instanceof CertificateResponseMessage);
        CertificateResponseMessage resp2 = (CertificateResponseMessage) o;
        assertEquals("Inherited object was not properly deserilized: ", ResponseStatus.SUCCESS.getValue(), resp2.getStatus().getValue());
    }

    /** Tests if we send a request with encrCert subsequentMessage (RFC4211 section 4.2) POP request, that we do get an
     * encrypted message back and we can decrypt the certificate. Only usable with ML-KEM keys.
     * Also verifies that encrCert can not be used with RSA, EC or ML-DSA keys, as only PQC KEM keys are allowed.
     * @throws CRLException
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws CMSException
     * @throws CertException
     * @throws CertificateException
     */
    @Test
    public void testCMPResponseMessageEncrCert() throws InvalidAlgorithmParameterException, OperatorCreationException, IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, CRLException, CMSException, CertificateException, CertException {

        // Create PKIMessages with encrCert POP
        final ProofOfPossession proofOfPossession = new ProofOfPossession(ProofOfPossession.TYPE_KEY_ENCIPHERMENT, new POPOPrivKey(SubsequentMessage.encrCert));
        final List<Certificate> cachain = Arrays.asList(cacert);

        // The first case, encrCert POP is only allowed with CMP v3
        // This is due to the usage of EnvelopedData, see RFC9480
        {
            // set pvno = 2 (CMP v2)
            final PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2000, eeKeysMLKEM, cacert.getIssuerX500Principal().getName(), eecertMLKEM.getSubjectX500Principal().getName(),
                    proofOfPossession);
            final CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");
            final CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull("Should manage to create a basic response message", resp);
            resp.setCertificate(eecertMLKEM);
            resp.setCACert(cacert);
            resp.create();
            // This should have created a response message, check it thoroughly
            final PKIMessage pkiMessage = PKIMessage.getInstance(resp.getResponseMessage());
            assertNotNull("Should be able to decode the response message", pkiMessage);
            final PKIBody pkiBody = pkiMessage.getBody();
            assertEquals("The returned message should be certInit response", PKIBody.TYPE_INIT_REP, pkiBody.getType());
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull("Response should contain certificate response", certRepMessage);
            assertNotNull("There should be one CertResponse", certResponse);

            assertEquals("RequestID in respone must be same as was sent in request", requestMessage.getRequestId(), certResponse.getCertReqId().getValue().intValue());
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull("PKI status must be there", pkiStatusInfo);
            assertEquals("Expected PKI response status " + ResponseStatus.FAILURE.getValue(), ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            assertEquals("Not the expected error message", "Got POP type TYPE_KEY_ENCIPHERMENT with CMP version 2, but required version is 3 (RFC9480)",
                    (pkiStatusInfo.getStatusString().getStringAtUTF8(0).getString()));
        }
        // The good path case, ML-KEM keys
        {
            final PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2021, eeKeysMLKEM, cacert.getIssuerX500Principal().getName(), eecertMLKEM.getSubjectX500Principal().getName(),
                    proofOfPossession);
            final CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");
            final CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull("Should manage to create a basic response message", resp);
            resp.setCertificate(eecertMLKEM);
            resp.setCACert(cacert);
            resp.create();
            // This should have created a response message, check it thoroughly
            final PKIMessage pkiMessage = PKIMessage.getInstance(resp.getResponseMessage());
            assertNotNull("Should be able to decode the response message", pkiMessage);
            final PKIBody pkiBody = pkiMessage.getBody();
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull("Response should contain certificate response", certRepMessage);
            assertNotNull("There should be one CertResponse", certResponse);

            assertEquals("RequestID in respone must be same as was sent in request", requestMessage.getRequestId(), certResponse.getCertReqId().getValue().intValue());
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull("PKI status must be there", pkiStatusInfo);
            assertEquals("Expected PKI response status " + ResponseStatus.SUCCESS.getValue(), ResponseStatus.SUCCESS.getValue(), pkiStatusInfo.getStatus().intValue());

            final CertifiedKeyPair certifiedKeyPair = certResponse.getCertifiedKeyPair();
            assertNotNull("The cert response should have a certificate (CertifiedKeyPair in CMP lingo)", certifiedKeyPair);
            final CertOrEncCert certOrEncCert = certifiedKeyPair.getCertOrEncCert();
            assertNotNull("There must be a CertorEncCert", certOrEncCert);
            assertTrue("We expect an encrypted cert, but the response doesn't have one.", certOrEncCert.hasEncryptedCertificate());
            final EncryptedKey encrCert = certOrEncCert.getEncryptedCert();
            ASN1Encodable asn1 = encrCert.getValue();
            // Should be a CMS EnvelopedData
            assertEquals("Encrypted value should be a CMS EnvelopedData", EnvelopedData.class.getName(), asn1.getClass().getName());

            // this is the preferred way of recovering an encrypted certificate, note the usage of slightly different classes for messages
            // See BC "PQC Almanac.pdf" for sample code from the BC team
            final CertificateRepMessage certificateRepMessage = CertificateRepMessage.fromPKIBody(pkiBody);
            final CertificateResponse certificateResp = certificateRepMessage.getResponses()[0];
            final CMPCertificate receivedCMPCert = certificateResp.getCertificate(new JceKEMEnvelopedRecipient(eeKeysMLKEM.getPrivate()));
            final X509CertificateHolder receivedCert = new X509CertificateHolder(receivedCMPCert.getX509v3PKCert());
            if (!receivedCert.isSignatureValid(new JcaContentVerifierProviderBuilder().build(cacert))) {
                assertTrue("Received certificate didn't verify againsts CA certificate", false);
            }
            // This is actually no point really, since the ee certificate in the response message was provided by ourselves from the beginning
            // But it's good sample code
            final X509Certificate cert = CertTools.getCertfromByteArray(receivedCert.getEncoded(), X509Certificate.class);
            assertEquals("Received cert public key should be ML-KEM", "ML-KEM-512", cert.getPublicKey().getAlgorithm());
            assertTrue("Public key in issued certificate is not identical to what we sent in request", Objects.deepEquals(eeKeysMLKEM.getPublic().getEncoded(), cert.getPublicKey().getEncoded()));

            // TODO: report to David, this throws
            //receivedCert.getSubjectPublicKeyInfo().parsePublicKey();
        }
        // Add failure tests as well, i.e. that an RSA, EC or ML-DSA key is not allowed with encrCert
        {
            final PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2021, eeKeysMLDSA, cacert.getIssuerX500Principal().getName(), eecertMLDSA.getSubjectX500Principal().getName(),
                    proofOfPossession);
            final CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");
            final CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull("Should manage to create a basic response message", resp);
            resp.setCertificate(eecertMLDSA);
            resp.setCACert(cacert);
            resp.create();
            // This should have created a response message, check it thoroughly
            final PKIMessage pkiMessage = PKIMessage.getInstance(resp.getResponseMessage());
            assertNotNull("Should be able to decode the response message", pkiMessage);
            final PKIBody pkiBody = pkiMessage.getBody();
            assertEquals("The returned message should be certInit response", PKIBody.TYPE_INIT_REP, pkiBody.getType());
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull("Response should contain certificate response", certRepMessage);
            assertNotNull("There should be one CertResponse", certResponse);

            assertEquals("RequestID in respone must be same as was sent in request", requestMessage.getRequestId(), certResponse.getCertReqId().getValue().intValue());
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull("PKI status must be there", pkiStatusInfo);
            assertEquals("Expected PKI response status " + ResponseStatus.FAILURE.getValue(), ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            assertEquals("Not the expected error message", "Got POP type TYPE_KEY_ENCIPHERMENT and SubsequentMessage, but request public key is not PQC: ML-DSA-44",
                    (pkiStatusInfo.getStatusString().getStringAtUTF8(0).getString()));
        }
        {
            final PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2021, eeKeysEC, cacert.getIssuerX500Principal().getName(), eecertEC.getSubjectX500Principal().getName(),
                    proofOfPossession);
            final CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");
            final CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull("Should manage to create a basic response message", resp);
            resp.setCertificate(eecertEC);
            resp.setCACert(cacert);
            resp.create();
            // This should have created a response message, check it thoroughly
            final PKIMessage pkiMessage = PKIMessage.getInstance(resp.getResponseMessage());
            assertNotNull("Should be able to decode the response message", pkiMessage);
            final PKIBody pkiBody = pkiMessage.getBody();
            assertEquals("The returned message should be certInit response", PKIBody.TYPE_INIT_REP, pkiBody.getType());
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull("Response should contain certificate response", certRepMessage);
            assertNotNull("There should be one CertResponse", certResponse);

            assertEquals("RequestID in respone must be same as was sent in request", requestMessage.getRequestId(), certResponse.getCertReqId().getValue().intValue());
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull("PKI status must be there", pkiStatusInfo);
            assertEquals("Expected PKI response status " + ResponseStatus.FAILURE.getValue(), ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            assertEquals("Not the expected error message", "Got POP type TYPE_KEY_ENCIPHERMENT and SubsequentMessage, but request public key is not PQC: EC",
                    (pkiStatusInfo.getStatusString().getStringAtUTF8(0).getString()));
        }
        {
            final PKIMessage myPKIMessage = createPKIMessage(PKIHeader.CMP_2021, eeKeysRSA, cacert.getIssuerX500Principal().getName(), eecertRSA.getSubjectX500Principal().getName(),
                    proofOfPossession);
            final CrmfRequestMessage requestMessage = new CrmfRequestMessage(myPKIMessage, cacert.getIssuerX500Principal().getName(), true, "CN");
            final CertificateResponseMessage resp = ResponseMessageUtils.createResponseMessage(CmpResponseMessage.class, requestMessage, cachain, caKeysMLDSA.getPrivate(), cacert.getSigAlgName(), BouncyCastleProvider.PROVIDER_NAME);
            assertNotNull("Should manage to create a basic response message", resp);
            resp.setCertificate(eecertRSA);
            resp.setCACert(cacert);
            resp.create();
            // This should have created a response message, check it thoroughly
            final PKIMessage pkiMessage = PKIMessage.getInstance(resp.getResponseMessage());
            assertNotNull("Should be able to decode the response message", pkiMessage);
            final PKIBody pkiBody = pkiMessage.getBody();
            assertEquals("The returned message should be certInit response", PKIBody.TYPE_INIT_REP, pkiBody.getType());
            final CertRepMessage certRepMessage = (CertRepMessage) pkiBody.getContent();
            final CertResponse certResponse = certRepMessage.getResponse()[0];
            assertNotNull("Response should contain certificate response", certRepMessage);
            assertNotNull("There should be one CertResponse", certResponse);

            assertEquals("RequestID in respone must be same as was sent in request", requestMessage.getRequestId(), certResponse.getCertReqId().getValue().intValue());
            // Verify response status
            final PKIStatusInfo pkiStatusInfo = certResponse.getStatus();
            assertNotNull("PKI status must be there", pkiStatusInfo);
            assertEquals("Expected PKI response status " + ResponseStatus.FAILURE.getValue(), ResponseStatus.FAILURE.getValue(), pkiStatusInfo.getStatus().intValue());
            assertEquals("Not the expected error message", "Got POP type TYPE_KEY_ENCIPHERMENT and SubsequentMessage, but request public key is not PQC: RSA",
                    (pkiStatusInfo.getStatusString().getStringAtUTF8(0).getString()));
        }
    }

    /**
     * @param pvno CMP version number, see RFC4210 and RFC9480, normally PKIHeader.CMP_2000 (CMPv2) but use PKIHeader.CMP_2021 (CMPv3) for RFC9480 features
     */
    private PKIMessage createPKIMessage(int pvno, KeyPair keys, final String issuerDN, final String subjectDN, ProofOfPossession pop) throws InvalidAlgorithmParameterException, IOException {
        ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
        org.bouncycastle.asn1.x509.Time nb = new org.bouncycastle.asn1.x509.Time(new DERGeneralizedTime("20030211002120Z"));
        org.bouncycastle.asn1.x509.Time na = new org.bouncycastle.asn1.x509.Time(new Date());
        optionalValidityV.add(new DERTaggedObject(true, 0, nb));
        optionalValidityV.add(new DERTaggedObject(true, 1, na));
        OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));

        CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
        myCertTemplate.setValidity(myOptionalValidity);
        myCertTemplate.setIssuer(new X500Name(issuerDN));
        myCertTemplate.setSubject(new X500Name(subjectDN));
        SubjectPublicKeyInfo keyInfo = SubjectPublicKeyInfo.getInstance(keys.getPublic().getEncoded());
        myCertTemplate.setPublicKey(keyInfo);

        // Not needed here, but good sample code
        AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
        AttributeTypeAndValue[] avs = { av };

        CertRequest myCertRequest = new CertRequest(4, myCertTemplate.build(), null);
        CertReqMsg myCertReqMsg = new CertReqMsg(myCertRequest, pop, avs);
        CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

        PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(pvno, new GeneralName(new X500Name("CN=bogusSubject")), new GeneralName(new X500Name("CN=bogusIssuer")));
        myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
        myPKIHeader.setSenderNonce(new DEROctetString(CmpMessageHelper.createSenderNonce()));
        myPKIHeader.setTransactionID(new DEROctetString(CmpMessageHelper.createSenderNonce()));
        PKIBody myPKIBody = new PKIBody(0, myCertReqMessages);
        PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
        return myPKIMessage;
    }


}
