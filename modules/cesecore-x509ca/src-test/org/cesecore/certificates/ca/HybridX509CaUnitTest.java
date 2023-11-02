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
package org.cesecore.certificates.ca;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AltSignatureAlgorithm;
import org.bouncycastle.asn1.x509.SubjectAltPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.cert.CertException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import org.cesecore.certificates.ca.catoken.CAToken;
import org.cesecore.certificates.ca.catoken.CATokenConstants;
import org.cesecore.certificates.certificate.CertificateCreateException;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.certificate.certextensions.CertificateExtensionException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.SoftCryptoToken;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestName;

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.StringTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

/**
 * Unit tests for verifying EJBCA's behavior when the CA has an alternate keypair.
 * 
 */
public class HybridX509CaUnitTest {

    @Rule
    public TestName testName = new TestName();

    private X509CA x509ca;
    private CryptoToken cryptoToken;

    @BeforeClass
    public static void beforeClass() {
        CryptoProviderTools.installBCProvider();
    }

    @Before
    public void setup() throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmParameterException,
            InvalidAlgorithmException, CAOfflineException, IllegalValidityException, IllegalNameException, OperatorCreationException,
            CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException {
        final String caDn = "CN=" + testName.getMethodName() + "_CA";
        final int cryptoTokenId = 17;

        //Construct a crypto token containing both keys
        final String cryptoTokenPassword = "foo123";
        final Properties cryptoTokenProperties = new Properties();
        cryptoTokenProperties.setProperty(CryptoToken.AUTOACTIVATE_PIN_PROPERTY, cryptoTokenPassword);
        try {
            cryptoToken = CryptoTokenFactory.createCryptoToken(SoftCryptoToken.class.getName(), cryptoTokenProperties, null, cryptoTokenId,
                    "CryptoToken's name");
        } catch (NoSuchSlotException e) {
            throw new IllegalStateException("Attempted to find a slot for a soft crypto token. This should not happen.", e);
        }
        cryptoToken.activate(cryptoTokenPassword.toCharArray());

        cryptoToken.generateKeyPair("secp256r1", CAToken.SOFTPRIVATESIGNKEYALIAS);
        cryptoToken.generateKeyPair(AlgorithmConstants.KEYALGORITHM_DILITHIUM2, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);

        // Create CAToken
        Properties caTokenProperties = constructCaTokenProperties();

        CAToken caToken = new CAToken(cryptoToken.getId(), caTokenProperties);
        // Set key sequence so that next sequence will be 00001 (this is the default though so not really needed here)
        caToken.setKeySequence(CAToken.DEFAULT_KEYSEQUENCE);
        caToken.setKeySequenceFormat(StringTools.KEY_SEQUENCE_FORMAT_NUMERIC);
        caToken.setSignatureAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        caToken.setEncryptionAlgorithm(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA);
        caToken.setAlternativeSignatureAlgorithm(AlgorithmConstants.SIGALG_DILITHIUM2);

        X509CAInfo cainfo = X509CAInfo.getDefaultX509CAInfo(caDn, "testHybridRootCa", CAConstants.CA_ACTIVE,
                CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA, "3650d", CAInfo.SELFSIGNED, null, caToken);

        x509ca = (X509CA) CAFactory.INSTANCE.getX509CAImpl(cainfo);
        x509ca.setCAToken(caToken);
        

        EndEntityInformation endEntityInformation = makeEndEntityInformation((X509CAInfo) x509ca.getCAInfo());

        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ROOTCA);
        
        X509Certificate caCertificate = (X509Certificate) x509ca.generateCertificate(cryptoToken, endEntityInformation,
                cryptoToken.getPublicKey(CAToken.SOFTPRIVATESIGNKEYALIAS), -1, null, x509ca.getCAInfo().getEncodedValidity(), certificateProfile, "0000", null);
        x509ca.setCertificateChain(Arrays.asList(caCertificate));
    }

    /**
     * Construct a vanilla X509 root CA with an P256 key as primary and Dilithium2 as alternative
     */
    @Test
    public void testHybridRootCa() throws InvalidAlgorithmParameterException, CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException,
            InvalidAlgorithmException, CAOfflineException, IllegalValidityException, IllegalNameException, OperatorCreationException,
            CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException, CertificateEncodingException,
            IOException, CertException {


        X509Certificate caCertificate = (X509Certificate) x509ca.getCertificateChain().get(0);

        assertTrue("Primary signing algorithm was oid incorrect: " + caCertificate.getSigAlgOID(),
                X9ObjectIdentifiers.ecdsa_with_SHA256.getId().equals(caCertificate.getSigAlgOID()));

        try {
            caCertificate.verify(caCertificate.getPublicKey());
        } catch (SignatureException | CertificateException | InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
            fail("Certificate did not verify using primary key");
        }

        assertEquals("Signature algorithm name mismatch: " + caCertificate.getSigAlgName(), AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA.toUpperCase(),
                caCertificate.getSigAlgName());

        X509CertificateHolder certHolder = new JcaX509CertificateHolder(caCertificate);
        PrivateKey alternativePrivateKey = cryptoToken.getPrivateKey(CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        ContentSigner altSigGen = new JcaContentSignerBuilder("Dilithium2").setProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
                .build(alternativePrivateKey);
        assertEquals("Incorrect alternative signature value", altSigGen.getAlgorithmIdentifier(),
                AltSignatureAlgorithm.fromExtensions(certHolder.getExtensions()));
        PublicKey alternativePublicKey = cryptoToken.getPublicKey(CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativePublicKey.getEncoded()),
                SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));

        assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(alternativePublicKey)));

    }

    @Test
    public void testEnrollHybridEndEntity() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException,
            OperatorCreationException, CryptoTokenOfflineException, CAOfflineException, InvalidAlgorithmException, IllegalValidityException,
            IllegalNameException, CertificateCreateException, SignatureException, IllegalKeyException, CertificateExtensionException, IOException, CertificateEncodingException, CertException {
        final String subjectDn = "CN=" + testName.getMethodName() + "_ee";
        
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_EC, BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec("P-256"));
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        KeyPairGenerator alternativeKeyPairGenerator = KeyPairGenerator.getInstance(AlgorithmConstants.KEYALGORITHM_DILITHIUM,
                BouncyCastleProvider.PROVIDER_NAME);
        alternativeKeyPairGenerator.initialize(DilithiumParameterSpec.dilithium2);
        KeyPair alternativeKeyPair = alternativeKeyPairGenerator.generateKeyPair();

        JcaPKCS10CertificationRequestBuilder jcaPKCS10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Name(subjectDn), keyPair.getPublic());

        ContentSigner altSigner = new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_DILITHIUM2)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(alternativeKeyPair.getPrivate());

        PKCS10CertificationRequest pkcs10CertificationRequest = jcaPKCS10CertificationRequestBuilder
                .build(new JcaContentSignerBuilder(AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .build(keyPair.getPrivate()), alternativeKeyPair.getPublic(), altSigner);
        
        PKCS10RequestMessage request = new PKCS10RequestMessage(pkcs10CertificationRequest.toASN1Structure().getEncoded());
        
        CertificateProfile certificateProfile = new CertificateProfile(CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER);
        
        EndEntityInformation endEntityInformation = new EndEntityInformation(testName.getMethodName(), subjectDn, x509ca.getSubjectDN().hashCode(), null, null, 0,
                new EndEntityType(EndEntityTypes.INVALID), 0, 0, null, null, 0, null);
        
        X509Certificate x509Certificate = (X509Certificate) x509ca.generateCertificate(cryptoToken, endEntityInformation, request, null, 0, null, null, certificateProfile, null,  "00000", null);
        
        X509CertificateHolder certHolder = new JcaX509CertificateHolder(x509Certificate);
        PrivateKey caAlternativePrivateKey = cryptoToken.getPrivateKey(CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        ContentSigner altSigGen = new JcaContentSignerBuilder(AlgorithmConstants.KEYALGORITHM_DILITHIUM2).setProvider(BouncyCastlePQCProvider.PROVIDER_NAME)
                .build(caAlternativePrivateKey);
        assertEquals("Incorrect alternative signature value", altSigGen.getAlgorithmIdentifier(),
                AltSignatureAlgorithm.fromExtensions(certHolder.getExtensions()));
        PublicKey alternativePublicKey = alternativeKeyPair.getPublic();
        assertEquals("Incorrect alternative public key", ASN1Primitive.fromByteArray(alternativePublicKey.getEncoded()),
                SubjectAltPublicKeyInfo.fromExtensions(certHolder.getExtensions()));
        PublicKey caAlternativePublicKey = cryptoToken.getPublicKey(CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        assertTrue("Alternative signature does not verify", certHolder.isAlternativeSignatureValid(
                new JcaContentVerifierProviderBuilder().setProvider(BouncyCastlePQCProvider.PROVIDER_NAME).build(caAlternativePublicKey)));

    }

    private Properties constructCaTokenProperties() {
        Properties caTokenProperties = new Properties();
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CRLSIGN_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_DEFAULT_STRING, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_NEXT, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_CERTSIGN_STRING_PREVIOUS, CAToken.SOFTPRIVATESIGNKEYALIAS);
        caTokenProperties.setProperty(CATokenConstants.CAKEYPURPOSE_ALTERNATIVE_CERTSIGN_STRING, CAToken.ALTERNATE_SOFT_PRIVATE_SIGNKEY_ALIAS);
        return caTokenProperties;
    }

    private EndEntityInformation makeEndEntityInformation(final X509CAInfo x509cainfo) {
        String caAltName = null;
        ExtendedInformation extendedinfo = null;

        caAltName = x509cainfo.getSubjectAltName();
        extendedinfo = new ExtendedInformation();
        extendedinfo.setNameConstraintsPermitted(x509cainfo.getNameConstraintsPermitted());
        extendedinfo.setNameConstraintsExcluded(x509cainfo.getNameConstraintsExcluded());

        return new EndEntityInformation(testName.getMethodName(), x509cainfo.getSubjectDN(), x509cainfo.getSubjectDN().hashCode(), caAltName, null, 0,
                new EndEntityType(EndEntityTypes.INVALID), 0, x509cainfo.getCertificateProfileId(), null, null, 0, extendedinfo);
    }
}
