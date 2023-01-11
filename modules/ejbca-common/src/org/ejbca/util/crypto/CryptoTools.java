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
package org.ejbca.util.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.spec.SecretKeySpec;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.crmf.EncKeyWithID;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.crmf.CRMFException;
import org.bouncycastle.cert.crmf.PKIArchiveControl;
import org.bouncycastle.cert.crmf.jcajce.JcaPKIArchiveControlBuilder;
import org.bouncycastle.cms.CMSAlgorithm;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyAgreeEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientId;
import org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.LookAheadObjectInputStream;
import org.ejbca.config.EjbcaConfiguration;

/**
 * This utility class contains static utility methods related to cryptographic functions.
 */
public class CryptoTools {
    
    public static final String BCRYPT_PREFIX = "$2a$";
    
    private static final Logger log = Logger.getLogger(CryptoTools.class);

    /**
     * Creates the hashed password using the bcrypt algorithm, http://www.mindrot.org/projects/jBCrypt/
     */
    public static String makePasswordHash(String password) {
        if (password == null) {
            return null;
        }
        final int rounds = EjbcaConfiguration.getPasswordLogRounds();
        if (rounds > 0) {
            return BCrypt.hashpw(password, BCrypt.gensalt(rounds));
        } else {
            return makeOldPasswordHash(password);
        }
    }

    /**
     * Creates the hashed password using the old hashing, which is a plain SHA1 password.
     * 
     * This was used for password creation until the EJBCA 4.0 release.
     */
    public static String makeOldPasswordHash(String password) {
        if (password == null) {
            return null;
        }
        String ret = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("SHA1");
            final byte[] pwdhash = md.digest(password.trim().getBytes());
            ret = new String(Hex.encode(pwdhash));
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA1 algorithm not supported.", e);
            throw new Error("SHA1 algorithm not supported.", e);
        }
        return ret;
    }

    /**
     * This method takes a BCrypt-generated password hash and extracts the salt element into cleartext.
     * 
     * @param passwordHash a BCrypt generated password hash.
     * @return the salt in cleartext.
     */
    public static String extractSaltFromPasswordHash(String passwordHash) {
        if(!passwordHash.startsWith(BCRYPT_PREFIX)) {
            throw new IllegalArgumentException("Provided string is not a BCrypt hash.");
        }
        //Locate the third '$', this is where the rounds declaration ends.
        int offset = passwordHash.indexOf('$', BCRYPT_PREFIX.length())+1;
        return passwordHash.substring(0, offset+22);            
    }
    
    /**
     * Encryption method used to encrypt a key pair using a CA
     *
     * @param cryptoToken the crypto token where the encryption key is
     * @param alias the alias of the key on the crypto token to use for encryption
     * @param keypair the data to encrypt
     * @return encrypted data
     * @throws CryptoTokenOfflineException If crypto token is off-line so encryption key can not be used.
     */
    public static byte[] encryptKeys(final X509Certificate caCertificate, final CryptoToken cryptoToken, final String alias,
            final KeyPair endEntityKeyPair) throws CryptoTokenOfflineException {
        byte[] result = null;
        switch (cryptoToken.getPublicKey(alias).getAlgorithm()) {
        case AlgorithmConstants.KEYALGORITHM_RSA:
            result = encryptKeysWithRsa(cryptoToken.getPublicKey(alias), endEntityKeyPair);
            break;
        case AlgorithmConstants.KEYALGORITHM_EC:
        case AlgorithmConstants.KEYALGORITHM_ECDSA:
            result = encryptPrivateKeyWithEccDh(caCertificate, cryptoToken, alias, endEntityKeyPair);
            break;    
            
        default:
            throw new IllegalStateException("Invalid encryption algorithm for key recovery: " + cryptoToken.getPublicKey(alias).getAlgorithm());
        }

        return result;
    }
    
    private static final byte[] encryptKeysWithRsa(final PublicKey encryptionKey, final KeyPair endEntityKeyPair)
            throws CryptoTokenOfflineException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(baos);
            os.writeObject(endEntityKeyPair);
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            byte[] keyId = KeyTools.createSubjectKeyId(encryptionKey).getKeyIdentifier();
            edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyId, encryptionKey));
            //We can use BC for the symmetric key since this doesn't happen in the HSM 
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC)
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME);
            CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(baos.toByteArray()), jceCMSContentEncryptorBuilder.build());
            return ed.getEncoded();
        } catch (IOException | CMSException e) {
            throw new IllegalStateException("Failed to encrypt keys: " + e.getMessage(), e);
        }
    }
    
    private static final byte[] encryptPrivateKeyWithEccDh(final X509Certificate caCertificate, final CryptoToken cryptoToken, final String alias,
            final KeyPair endEntityKeyPair) throws CryptoTokenOfflineException {
        final String providerName = cryptoToken.getEncProviderName();
        JceKeyAgreeRecipientInfoGenerator keyAgreeRecipientInfoGenerator;
        try {
            keyAgreeRecipientInfoGenerator = new JceKeyAgreeRecipientInfoGenerator(CMSAlgorithm.ECCDH_SHA256KDF, cryptoToken.getPrivateKey(alias),
                   caCertificate.getPublicKey(), CMSAlgorithm.AES256_WRAP).addRecipient(caCertificate).setProvider(providerName);
            JcaPKIArchiveControlBuilder pkIArchiveControlBuilder = new JcaPKIArchiveControlBuilder(endEntityKeyPair.getPrivate(),
                    caCertificate.getSubjectX500Principal());
            pkIArchiveControlBuilder.addRecipientGenerator(keyAgreeRecipientInfoGenerator);
            //We can use BC for the symmetric key since this doesn't happen in the HSM 
            PKIArchiveControl pkiArchiveControl = pkIArchiveControlBuilder
                    .build(new JceCMSContentEncryptorBuilder(new ASN1ObjectIdentifier(CMSEnvelopedDataGenerator.AES256_CBC))
                            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build());
            CMSEnvelopedData cmsEnvelopedData = pkiArchiveControl.getEnvelopedData();
            return cmsEnvelopedData.getEncoded();
        } catch (CertificateEncodingException | CMSException | IOException | CRMFException e) {
            throw new IllegalStateException("Failed to encrypt keys: " + e.getMessage(), e);
        }

    }

    /**
     * Encryption method used to encrypt a shared key pair using a CA.
     * 
     * @param cryptoToken the crypto token where the encryption key is.
     * @param alias the alias of the key on the crypto token to use for encryption.
     * @param key the data to encrypt.
     * @return encrypted data.
     * 
     * @throws CryptoTokenOfflineException If crypto token is off-line so encryption key can not be used.
     */
    public static byte[] encryptKey(final CryptoToken cryptoToken, final String alias, final SecretKeySpec key) throws CryptoTokenOfflineException {
        log.info("Encrypt key using key alias '" + alias + "' from Crypto Token " + cryptoToken.getId());
        return encryptKey(cryptoToken.getPublicKey(alias), key);
    }
    
    /**
     * Encryption method used to encrypt a shared key pair using a public key.
     * 
     * @param pk the public key to encrypt the data.
     * @param key the data to encrypt.
     * @return encrypted data.
     */
    public static byte[] encryptKey(final PublicKey pk, final SecretKeySpec key) {
        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
             ObjectOutputStream os = new ObjectOutputStream(baos)) {
            os.writeObject(key);
            final CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();
            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
            final byte[] keyId = KeyTools.createSubjectKeyId(pk).getKeyIdentifier();
            generator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyId, pk));
            final JceCMSContentEncryptorBuilder builder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            final CMSEnvelopedData data = generator.generate(new CMSProcessableByteArray(baos.toByteArray()), builder.build());
            return data.getEncoded();
        } catch (IOException | CMSException e) {
            throw new IllegalStateException("Failed to encrypt key: " + e.getMessage(), e);
        }
    }

    /**
     * Decryption method used to decrypt a key pair using a CA
     *
     * @param provider the provider used to encrypt this keypair, e.g. BouncyCastle 
     * @param cacCertificate the certificate of the signing CA
     * @param decryptionKey the decryption key
     * @param data the encrypted blob of data
     *
     * @return the decrypted KeyPair
     * @throws CryptoTokenOfflineException If crypto token is off-line so decryption key can not be used.
     * @throws IOException In case reading/writing data streams failed during decryption, or parsing decrypted data into KeyPair.
     * @throws NoSuchProviderException if the sought provider was not found
     */
    public static final KeyPair decryptKeys(final String provider, final X509Certificate cacCertificate, final PrivateKey decryptionKey, final byte[] data) throws IOException, CryptoTokenOfflineException, NoSuchProviderException {
        KeyPair result;       
        switch (decryptionKey.getAlgorithm()) {
        case AlgorithmConstants.KEYALGORITHM_RSA:
            result = decryptKeysWithRsa(provider, decryptionKey, data);
            break;
        case AlgorithmConstants.KEYALGORITHM_EC:
        case AlgorithmConstants.KEYALGORITHM_ECDSA:
            final ECPrivateKey privateKey = decryptPrivateKeyWithEccDH(provider, cacCertificate, decryptionKey, data);
            ECParameterSpec ecParams = privateKey.getParameters();
            ECPoint q = ecParams.getG().multiply(privateKey.getD());

            ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(q, ecParams);
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance("EC", provider);
            } catch (NoSuchAlgorithmException e) {         
                throw new IllegalStateException("ECDH was not a known algorithm for provider.", e);
            } 
            PublicKey publicKey;
            try {
                publicKey = keyFactory.generatePublic(publicKeySpec);
            } catch (InvalidKeySpecException e) {
                throw new IOException("Could not recreate public key.", e);
            }
           
            result = new KeyPair(publicKey, privateKey);
            break;    
            
        default:
            throw new IllegalStateException("Invalid encryption algorithm for key recovery: " + decryptionKey.getAlgorithm());
        }
        return result;

    }
    
    private static final ECPrivateKey decryptPrivateKeyWithEccDH(final String provider, final X509Certificate caCertificate, final PrivateKey decryptionKey, byte[] data) throws IOException {
        CMSEnvelopedData cmsEnvelopedData;
        try {
            cmsEnvelopedData = new CMSEnvelopedData(data);          
            RecipientInformationStore recipientInformationStore = cmsEnvelopedData.getRecipientInfos();
            JceKeyAgreeRecipientId recipientId = new JceKeyAgreeRecipientId(caCertificate);
            RecipientInformation recipientInformation = recipientInformationStore.get(recipientId);
            Recipient recipient = new JceKeyAgreeEnvelopedRecipient(decryptionKey).setProvider(provider);
            byte[] content = recipientInformation.getContent(recipient);
            EncKeyWithID encKeyWithID = EncKeyWithID.getInstance(content);
            PrivateKeyInfo privateKeyInfo = encKeyWithID.getPrivateKey();
            return (ECPrivateKey) BouncyCastleProvider.getPrivateKey(privateKeyInfo);            
        } catch (CMSException e) {
            throw new IOException("Could not parse encrypted data: " + e.getMessage(), e);
        }   
    
    }
    
    private static final KeyPair decryptKeysWithRsa(final String provider, final PrivateKey decryptionKey, final byte[] data) throws CryptoTokenOfflineException, IOException {
        try {
            CMSEnvelopedData ed = new CMSEnvelopedData(data);
            RecipientInformationStore recipients = ed.getRecipientInfos();
            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(decryptionKey);
            rec.setProvider(provider);
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM,
            // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known
            // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
            rec.setMustProduceEncodableUnwrappedKey(true);
            byte[] recdata = recipient.getContent(rec);
            try (LookAheadObjectInputStream ois = new LookAheadObjectInputStream(new ByteArrayInputStream(recdata))) {
                // we have things like:
                // org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey implements [interface org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey] 
                // and...
                // public interface EdDSAPrivateKey extends EdDSAKey, PrivateKey
                // We can set the interface (EdDSAPrivateKey) to accepted by using setEnabledInterfaceImplementations, 
                // but as the interface extends java.security.PrivateKey the setEnabledSubclassing does not work for class->implementing interface->extending
                // as the class itself does not extend java.security.PrivateKey
                // that doesn't work even for RSA, so we need to add the specific interfaces 
                Set<Class<? extends Serializable>> keypairclasses = new HashSet<Class<? extends Serializable>>();
                keypairclasses.add(java.security.KeyPair.class);
                keypairclasses.add(java.security.interfaces.RSAPrivateKey.class);
                keypairclasses.add(java.security.interfaces.RSAPublicKey.class);
                keypairclasses.add(java.security.interfaces.ECPrivateKey.class);
                keypairclasses.add(java.security.interfaces.ECPublicKey.class);
                keypairclasses.add(org.bouncycastle.jcajce.interfaces.EdDSAPrivateKey.class);
                keypairclasses.add(org.bouncycastle.jcajce.interfaces.EdDSAPublicKey.class);
                keypairclasses.add(java.security.interfaces.DSAPrivateKey.class);
                keypairclasses.add(java.security.interfaces.DSAPublicKey.class);
                ois.setAcceptedClasses(keypairclasses);
                // only allow BC to implement key classes, which should work since we use BC to read the CMS structure, which will create BC keys internally
                ois.setEnabledInterfaceImplementations(true, "org.bouncycastle"); 
                // public and private keys contain a lot of BigIntegers and such, but 50 seems to work for all keys I tried (RSA, EC, EdDSA, DSA)
                ois.setMaxObjects(50);
                return (KeyPair) ois.readObject();                
            }
        } catch (ClassNotFoundException e) {
            throw new IOException("Could not deserialize key pair after decrypting it due to missing class: " + e.getMessage(), e);
        } catch (CMSException e) {
            throw new IOException("Could not parse encrypted data: " + e.getMessage(), e);
        }
    }
    
    /**
     * Decryption method used to decrypt a symmetric key using a CA.
     * 
     * @param cryptoToken the crypto token where the decryption key is.
     * @param alias the alias of the key on the crypto token to use for decryption.
     * @param data the data to decrypt.
     * @return a symmetric key as SecretKeySpec.
     * @throws CryptoTokenOfflineException If crypto token is off-line so decryption key can not be used.
     * @throws IOException In case reading/writing data streams failed during decryption, or parsing decrypted data into SecretKeySpec.
     */
    public static final SecretKeySpec decryptKey(final CryptoToken cryptoToken, final String alias, final byte[] data) throws IOException, CryptoTokenOfflineException {
        try {
            final CMSEnvelopedData ed = new CMSEnvelopedData(data);
            final RecipientInformationStore recipients = ed.getRecipientInfos();
            final RecipientInformation recipient = recipients.getRecipients().iterator().next();
            final JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(cryptoToken.getPrivateKey(alias));
            rec.setProvider(cryptoToken.getEncProviderName()); 
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM,
            // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known
            // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
            rec.setMustProduceEncodableUnwrappedKey(true);
            SecretKeySpec spec; 
            try (LookAheadObjectInputStream ois = new LookAheadObjectInputStream(new ByteArrayInputStream(recipient.getContent(rec)))) {
                Set<Class<? extends Serializable>> keypairclasses = new HashSet<Class<? extends Serializable>>();
                keypairclasses.add(javax.crypto.spec.SecretKeySpec.class);
                ois.setAcceptedClasses(keypairclasses);
                // secret key sects contain other object, this works for all keys I tried (AES)
                ois.setMaxObjects(10);
                spec = (SecretKeySpec) ois.readObject();
                log.info("Decrypted key using key alias '" + alias + "' from Crypto Token " + cryptoToken.getId());
            } catch(IOException e) {
                throw e;
            }
            return spec;
        } 
        catch (ClassNotFoundException e) {
            throw new IOException("Could not deserialize key after decrypting it due to missing class: " + e.getMessage(), e);
        }
        catch (CMSException e) {
            throw new IOException("Could not parse encrypted data: " + e.getMessage(), e);
        }
    }

}
