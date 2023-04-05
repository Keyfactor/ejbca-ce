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

import java.security.InvalidAlgorithmParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Collection;
import java.util.Iterator;
import java.util.Properties;

import com.keyfactor.commons.p11ng.provider.JackNJI11Provider;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenAuthenticationFailedException;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;
import com.keyfactor.util.keys.token.KeyGenParams;
import com.keyfactor.util.keys.token.KeyGenParams.KeyPairTemplate;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.RSAESOAEPparams;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.keys.token.PKCS11CryptoToken;
import org.junit.After;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assume.assumeTrue;

/**
 * Test class for Pkcs11Ng functions, generating testing and deleting keys on a Crypto Token using P11NG.
 * 
 */
public class Pkcs11NgCryptoTokenTest extends CryptoTokenTestBase {

    private static final String JACKNJI_NAME = "org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken";

    
    CryptoToken token = null;
    
    @BeforeClass
    public static void beforeClass() {
        assumeTrue(getHSMLibrary() != null);
        assumeTrue(getHSMProvider() != null);
        CryptoProviderTools.installBCProviderIfNotAvailable();
    }

    @After
    public void tearDown() {
        // Make sure we remove the provider after one test, so it is not still there affecting the next test
        Security.removeProvider(getProvider());
    }
    
    @Test
    public void testCryptoTokenRSA() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenRSA(token);
    }

    @Test
    public void testCryptoTokenRSACipher() throws Exception {
        CryptoToken cryptoToken = createPkcs11NgToken();
        cryptoToken.deactivate();

        cryptoToken.activate(tokenpin.toCharArray());
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());
        try {
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
            cryptoToken.generateKeyPair(KeyGenParams.builder("1024").withKeyPairTemplate(KeyPairTemplate.SIGN_ENCRYPT).build(), 
                    PKCS11TestUtils.RSA_TEST_KEY_1);
            //cryptoToken.generateKeyPair(PKCS11TestUtils.KEY_SIZE_1024, PKCS11TestUtils.RSA_TEST_KEY_1);
            PrivateKey priv = cryptoToken.getPrivateKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            PublicKey pub = cryptoToken.getPublicKey(PKCS11TestUtils.RSA_TEST_KEY_1);
            
            // RSA_PKCS key encryption
            doCipher(cryptoToken, priv, pub, new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption));
            
            // RSAES_OAEP key encryption, default OAEP parameters, SHA1, MGF1
            final RSAESOAEPparams paramsSHA1 = new RSAESOAEPparams();
            doCipher(cryptoToken, priv, pub, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, paramsSHA1));

            // RSAES_OAEP key encryption, custom OAEP parameters, SHA256, MGF1
            // SoftHSM2 does not support OAEP with SHA256 (my version on April 5 2023), but Thales DPoD does. 
            // Test disabled as SoftHSM doesn't support it, tested manually on DPoD with clientToolBox SCEPTest
            // see https://stackoverflow.com/questions/64888751/rsa-oaep-encryption-with-sha-256-fails-while-with-sha-1-is-ok
//            final RSAESOAEPparams paramsSHA256 = new RSAESOAEPparams(
//                    new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE), 
//                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_mgf1, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256, DERNull.INSTANCE)),
//                    new AlgorithmIdentifier(PKCSObjectIdentifiers.id_pSpecified, new DEROctetString(new byte[0])));
//            doCipher(cryptoToken, priv, pub, new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSAES_OAEP, paramsSHA256));
        } finally {
            // Clean up and delete our generated keys
            cryptoToken.deleteEntry(PKCS11TestUtils.RSA_TEST_KEY_1);
        }

//        doCryptoTokenRSA(token);
    }

    private void doCipher(CryptoToken cryptoToken, PrivateKey priv, PublicKey pub, AlgorithmIdentifier keyEncryptAlg) throws CMSException {
        // Create an enveloped CMS message, using AES encryption and RSAES_OAEP key wrapping
        // Symmetric key encryption in BC, public key wrapping also in BC
        CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
        edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator("keyIdentifier".getBytes(), keyEncryptAlg, pub).setProvider(BouncyCastleProvider.PROVIDER_NAME));
        JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.aES256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
        CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray("thisisdata".getBytes()), jceCMSContentEncryptorBuilder.build());
        
        // Now try to decrypt the message, unwrapping the symmetric key with the private key that is in the HSM
        JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(priv);
        rec.setProvider(cryptoToken.getEncProviderName()); // Use the crypto token provides for asymmetric key operations
        rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME); // Use BC for the symmetric key operations
        rec.setMustProduceEncodableUnwrappedKey(true);                              

        RecipientInformationStore recipients = ed.getRecipientInfos();
        Collection<RecipientInformation> c = recipients.getRecipients();
        Iterator<RecipientInformation> it = c.iterator();
        RecipientInformation recipient = (RecipientInformation) it.next();
        byte [] decBytes = recipient.getContent(rec);
        assertNotNull("Decryption should result in some bytes", decBytes);
        assertEquals("Decryption did not yield the correct result", "thisisdata", new String(decBytes));
    }

    @Test
    public void testCryptoTokenECC() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenECC(token, "secp256r1", 256, "secp384r1", 384);
    }

    /** Needs a rather new version of SoftHSM2 to pass this test, one that includes support for EdDSA */
    @Ignore
    public void testCryptoTokenEd25519() throws Exception {
        // HSMs only support Ed25519 so far (October 2020), not Ed448
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenECC(token, "Ed25519", 255, "Ed25519", 255);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void testCryptoTokenDSA() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doCryptoTokenDSA(token);
    }
    
    @Test
    public void testActivateDeactivate() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doActivateDeactivate(token);
    }
    
    @Test
    public void testAutoActivate() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doAutoActivate(token);
    }
    
    @Test
    public void testStoreAndLoad() throws Exception {
        token = createPkcs11NgToken();
        token.deactivate();
        doStoreAndLoad(token);
    }
    
    private static CryptoToken createPkcs11NgToken() throws NoSuchSlotException {
        return createPkcs11NgTokenWithAttributesFile(null, null, true);
    }
    
    private static CryptoToken createPkcs11NgTokenWithAttributesFile(String file, String tokenName, boolean extractable) throws NoSuchSlotException {
        Properties prop = new Properties();
        String hsmlib = getHSMLibrary();
        assertNotNull(hsmlib);
        prop.setProperty(PKCS11CryptoToken.SHLIB_LABEL_KEY, hsmlib);
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_VALUE, getPkcs11SlotValue());
        prop.setProperty(PKCS11CryptoToken.SLOT_LABEL_TYPE, getPkcs11SlotType().getKey());
        if (file != null) {
            prop.setProperty(PKCS11CryptoToken.ATTRIB_LABEL_KEY, file);
        }
        prop.setProperty(CryptoToken.ALLOW_EXTRACTABLE_PRIVATE_KEY, "False");
        CryptoToken token = createCryptoToken(JACKNJI_NAME, prop, null, 111, "P11Ng CryptoToken");
        return token;
    }

    @Override
    protected String getProvider() {
        return JackNJI11Provider.NAME;
    }
    
    @Override
    protected void doCryptoTokenDSA(CryptoToken cryptoToken) throws CryptoTokenOfflineException, CryptoTokenAuthenticationFailedException, InvalidAlgorithmParameterException  {
        // We have not activated the token so status should be offline
        assertEquals(CryptoToken.STATUS_OFFLINE, cryptoToken.getTokenStatus());
        assertEquals(getProvider(), cryptoToken.getSignProviderName());

        cryptoToken.activate(tokenpin.toCharArray());
        // Should still be ACTIVE now, because we run activate
        assertEquals(CryptoToken.STATUS_ACTIVE, cryptoToken.getTokenStatus());

        // Generate a DSA key and wait for exception because DSA keys are not supported with this token type.
        cryptoToken.generateKeyPair("DSA1024", "dsatest00001");
    }
}
