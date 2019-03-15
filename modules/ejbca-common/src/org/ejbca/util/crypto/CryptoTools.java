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
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
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
import org.bouncycastle.util.encoders.Hex;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;
import org.ejbca.config.EjbcaConfiguration;

/**
 * This utility class contains static utility methods related to cryptographic functions.
 * 
 * @version $Id$
 * 
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
    public static byte[] encryptKeys(final CryptoToken cryptoToken, final String alias, final KeyPair keypair) throws CryptoTokenOfflineException {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            ObjectOutputStream os = new ObjectOutputStream(baos);
            os.writeObject(keypair);
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            CMSEnvelopedData ed;
            // Creating the KeyId may just throw an exception, we will log this but store the cert and ignore the error
            final PublicKey pk = cryptoToken.getPublicKey(alias);
            byte[] keyId = KeyTools.createSubjectKeyId(pk).getKeyIdentifier();
            edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(keyId, pk));
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(NISTObjectIdentifiers.id_aes256_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            ed = edGen.generate(new CMSProcessableByteArray(baos.toByteArray()), jceCMSContentEncryptorBuilder.build());
            log.info("Encrypted keys using key alias '"+alias+"' from Crypto Token "+cryptoToken.getId());
            return ed.getEncoded();
        } catch (IOException | CMSException e) {
            throw new IllegalStateException("Failed to encrypt keys: " + e.getMessage(), e);
        }
    }

    /**
     * Decryption method used to decrypt a key pair using a CA
     *
     * @param cryptoToken the crypto token where the decryption key is
     * @param alias the alias of the key on the crypto token to use for decryption
     * @param data the data to decrypt
     * @return a KeyPair
     * @throws CryptoTokenOfflineException If crypto token is off-line so decryption key can not be used.
     * @throws IOException In case reading/writing data streams failed during decryption, or parsing decrypted data into KeyPair.
     */
    public static KeyPair decryptKeys(final CryptoToken cryptoToken, final String alias, final byte[] data) throws IOException, CryptoTokenOfflineException {
        try {
            CMSEnvelopedData ed = new CMSEnvelopedData(data);
            RecipientInformationStore recipients = ed.getRecipientInfos();
            RecipientInformation recipient = recipients.getRecipients().iterator().next();
            ObjectInputStream ois = null;
            JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(cryptoToken.getPrivateKey(alias));
            rec.setProvider(cryptoToken.getEncProviderName());
            rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
            // Option we must set to prevent Java PKCS#11 provider to try to make the symmetric decryption in the HSM,
            // even though we set content provider to BC. Symm decryption in HSM varies between different HSMs and at least for this case is known
            // to not work in SafeNet Luna (JDK behavior changed in JDK 7_75 where they introduced imho a buggy behavior)
            rec.setMustProduceEncodableUnwrappedKey(true);
            byte[] recdata = recipient.getContent(rec);
            ois = new ObjectInputStream(new ByteArrayInputStream(recdata));
            log.info("Decrypted keys using key alias '"+alias+"' from Crypto Token "+cryptoToken.getId());
            return (KeyPair) ois.readObject();
        } catch (ClassNotFoundException e) {
            throw new IOException("Could not deserialize key pair after decrypting it due to missing class: " + e.getMessage(), e);
        } catch (CMSException e) {
            throw new IOException("Could not parse encrypted data: " + e.getMessage(), e);
        }
    }

}
