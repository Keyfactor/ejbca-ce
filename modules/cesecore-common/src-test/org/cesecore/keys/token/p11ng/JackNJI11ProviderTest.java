/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/

package org.cesecore.keys.token.p11ng;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.bsi.BSIObjectIdentifiers;
import org.bouncycastle.asn1.cryptopro.CryptoProObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.isara.IsaraObjectIdentifiers;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSASSAPSSparams;
import org.bouncycastle.asn1.rosstandart.RosstandartObjectIdentifiers;
import org.bouncycastle.asn1.teletrust.TeleTrusTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.BufferingContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.PKCS11TestUtils;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;
import org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken;
import org.cesecore.keys.token.p11ng.provider.JackNJI11Provider;
import org.cesecore.util.CryptoProviderTools;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @version $Id$
 */
public class JackNJI11ProviderTest {

    private static final Map<ASN1ObjectIdentifier, String> oids = new HashMap<ASN1ObjectIdentifier, String>();
    
    static
    {
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), "SHA1WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha224WithRSAEncryption, "SHA224WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha256WithRSAEncryption, "SHA256WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha384WithRSAEncryption, "SHA384WITHRSA");
        oids.put(PKCSObjectIdentifiers.sha512WithRSAEncryption, "SHA512WITHRSA");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_94, "GOST3411WITHGOST3410");
        oids.put(CryptoProObjectIdentifiers.gostR3411_94_with_gostR3410_2001, "GOST3411WITHECGOST3410");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_256, "GOST3411-2012-256WITHECGOST3410-2012-256");
        oids.put(RosstandartObjectIdentifiers.id_tc26_signwithdigest_gost_3410_12_512, "GOST3411-2012-512WITHECGOST3410-2012-512");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA1, "SHA1WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA224, "SHA224WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA256, "SHA256WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA384, "SHA384WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_SHA512, "SHA512WITHPLAIN-ECDSA");
        oids.put(BSIObjectIdentifiers.ecdsa_plain_RIPEMD160, "RIPEMD160WITHPLAIN-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_1, "SHA1WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_224, "SHA224WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_256, "SHA256WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_384, "SHA384WITHCVC-ECDSA");
        oids.put(EACObjectIdentifiers.id_TA_ECDSA_SHA_512, "SHA512WITHCVC-ECDSA");
        oids.put(IsaraObjectIdentifiers.id_alg_xmss, "XMSS");
        oids.put(IsaraObjectIdentifiers.id_alg_xmssmt, "XMSSMT");

        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.4"), "MD5WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.113549.1.1.2"), "MD2WITHRSA");
        oids.put(new ASN1ObjectIdentifier("1.2.840.10040.4.3"), "SHA1WITHDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA1, "SHA1WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA224, "SHA224WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA256, "SHA256WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA384, "SHA384WITHECDSA");
        oids.put(X9ObjectIdentifiers.ecdsa_with_SHA512, "SHA512WITHECDSA");
        oids.put(OIWObjectIdentifiers.sha1WithRSA, "SHA1WITHRSA");
        oids.put(OIWObjectIdentifiers.dsaWithSHA1, "SHA1WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha224, "SHA224WITHDSA");
        oids.put(NISTObjectIdentifiers.dsa_with_sha256, "SHA256WITHDSA");

        oids.put(OIWObjectIdentifiers.idSHA1, "SHA1");
        oids.put(NISTObjectIdentifiers.id_sha224, "SHA224");
        oids.put(NISTObjectIdentifiers.id_sha256, "SHA256");
        oids.put(NISTObjectIdentifiers.id_sha384, "SHA384");
        oids.put(NISTObjectIdentifiers.id_sha512, "SHA512");
        oids.put(TeleTrusTObjectIdentifiers.ripemd128, "RIPEMD128");
        oids.put(TeleTrusTObjectIdentifiers.ripemd160, "RIPEMD160");
        oids.put(TeleTrusTObjectIdentifiers.ripemd256, "RIPEMD256");
    }
    
    private static final int MAX_SIGN_BUFFER_SIZE = 20480;
    public static final String tokenpin = PKCS11TestUtils.getPkcs11SlotPin();
    private static CryptoToken cryptoToken;
    
    @BeforeClass
    public static void beforeClass() {
        assumeTrue("No HSM library configured", PKCS11TestUtils.getHSMLibrary() != null);
        assumeTrue("No PKCS#11 Provider configured", PKCS11TestUtils.getHSMProvider() != null);
    }
    
    @Before
    public void setup() throws Exception {
        CryptoProviderTools.installBCProviderIfNotAvailable();
        Security.addProvider(new JackNJI11Provider());
        cryptoToken = createPkcs11NgTokenWithAttributesFile();
        cryptoToken.activate(tokenpin.toCharArray());
        cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_2048, PKCS11TestUtils.RSA_TEST_KEY_1);
        cryptoToken.generateKeyPair("secp256r1", PKCS11TestUtils.ECC_TEST_KEY_1);
    }
    
    @After
    public void tearDown() throws Exception {
        // Delete created HSM keys. CryptoToken is never persiste.
        cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        cryptoToken.deleteEntry(PKCS11TestUtils.ECC_TEST_KEY_1);
    }
    
    @Test
    public void testSignatureRsa() throws Exception {
        signWithProvider("SHA256withRSA", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA384withRSA", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA512withRSA", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
    }
    
    @Test
    public void testSignatureRsaWithMfg1() throws Exception {
        signWithProvider("SHA256withRSAandMGF1", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA384withRSAandMGF1", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA512withRSAandMGF1", PKCS11TestUtils.RSA_TEST_KEY_1, cryptoToken.getSignProviderName());
    }
    
    @Test
    public void testSignatureEcdsa() throws Exception {
        signWithProvider("SHA256withECDSA", PKCS11TestUtils.ECC_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA384withECDSA", PKCS11TestUtils.ECC_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA512withECDSA", PKCS11TestUtils.ECC_TEST_KEY_1, cryptoToken.getSignProviderName());
        signWithProvider("SHA256withECDSA", PKCS11TestUtils.ECC_TEST_KEY_1, cryptoToken.getSignProviderName());
    }
    
    @Test
    public void testPssParams() throws GeneralSecurityException, IOException {
        testDefaultPSSParams("SHA256withRSAandMGF1");
        testDefaultPSSParams("SHA384withRSAandMGF1");
        testDefaultPSSParams("SHA512withRSAandMGF1");
    }

    private void signWithProvider(final String algorithm, final String keyAlias , final String provider) throws Exception {
        final PrivateKey privKey = cryptoToken.getPrivateKey(keyAlias);
        assertEquals("JackNJI11Provider was not used.", JackNJI11Provider.NAME, cryptoToken.getSignProviderName());
        new BufferingContentSigner(new JcaContentSignerBuilder(algorithm).setProvider(provider).build(privKey), MAX_SIGN_BUFFER_SIZE);
    }
    
    // Create a P11NgCryptoToken using whichever library is installed
    private static CryptoToken createPkcs11NgTokenWithAttributesFile() throws NoSuchSlotException {
        Properties prop = new Properties();
        String hsmlib = PKCS11TestUtils.getHSMLibrary();
        assertNotNull("No HSM library installed for testing", hsmlib);
        prop.setProperty(Pkcs11NgCryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(Pkcs11NgCryptoToken.SLOT_LABEL_VALUE, PKCS11TestUtils.getPkcs11SlotValue());
        prop.setProperty(Pkcs11NgCryptoToken.SLOT_LABEL_TYPE, PKCS11TestUtils.getPkcs11SlotType().getKey());
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        return CryptoTokenFactory.createCryptoToken(CryptoTokenFactory.JACKNJI_NAME, prop, null, 111, "JackNJI11ProviderTestToken");
    }

    // Make sure PSS parameter configuraion is returned correctly.
    private void testDefaultPSSParams(final String algorithm) throws GeneralSecurityException, IOException {
        AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
        assertTrue(algorithm + " was not RSASSA-PSS", sigAlgId.getAlgorithm().equals(PKCSObjectIdentifiers.id_RSASSA_PSS));
        ASN1Sequence seq = ASN1Sequence.getInstance(sigAlgId.getParameters());
        if (seq == null || seq.size() == 0) {
            fail("Input sequence was empty");
        }
        RSASSAPSSparams pssParams = RSASSAPSSparams.getInstance(seq);
        AlgorithmIdentifier digAlgId = pssParams.getHashAlgorithm();
        String digAlgName = MessageDigestUtils.getDigestName(digAlgId.getAlgorithm());
        MessageDigest digest;
        try {
            // Since the JackNJI11Provider doesn't implement proper MessageDigest we use BC. This is the way it
            // is done through all calls to MessageDigest in EJBCA code.
            digest = MessageDigest.getInstance(digAlgName, BouncyCastleProvider.PROVIDER_NAME);
        } catch (NoSuchAlgorithmException e) {
            if (oids.get(digAlgId.getAlgorithm()) != null) {
                String altDigAlgName = (String)oids.get(digAlgId.getAlgorithm());
                digest = MessageDigest.getInstance(altDigAlgName, BouncyCastleProvider.PROVIDER_NAME);
            } else {
                throw e;
            }
        }
        AlgorithmParameters algParams = AlgorithmParameters.getInstance("PSS", JackNJI11Provider.NAME);
        algParams.init(seq.getEncoded());
        assertNotNull("PSSParameterSpec is null.", algParams.getParameterSpec(PSSParameterSpec.class));
        assertEquals("Mask generation function wasn't MGF1.", PKCSObjectIdentifiers.id_mgf1, pssParams.getMaskGenAlgorithm().getAlgorithm());
        assertEquals("hashAlgorithm and maskGenAlgorithm should be the same.", 
                pssParams.getHashAlgorithm(), AlgorithmIdentifier.getInstance(pssParams.getMaskGenAlgorithm().getParameters()));
        assertEquals("Salt length and digest length should be equal.", pssParams.getSaltLength().intValue(), digest.getDigestLength());
    }
    
}
