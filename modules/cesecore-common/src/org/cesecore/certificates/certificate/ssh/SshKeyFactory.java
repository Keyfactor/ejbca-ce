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
package org.cesecore.certificates.certificate.ssh;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import org.bouncycastle.util.encoders.Base64;

import com.keyfactor.util.keys.KeyTools;

/**
 * SSH Key Factory.
 * @version $Id$
 */
public enum SshKeyFactory {
    INSTANCE;
        
    /**
     * Sorts potential instances by their SSH prefixes, e.g. ecdsa-sha2-nistp384
     */
    private final Map<String, Class<? extends SshPublicKey>> sshKeyImplementations = new HashMap<>();

    /**
     * Sorts potential instances by their official implementations, e.g EC
     */
    private final Map<String, Class<? extends SshPublicKey>> publicKeyImplementations = new HashMap<>();

    SshKeyFactory() {
        for (SshPublicKey sshPublicKey : ServiceLoader.load(SshPublicKey.class)) {
            for (String keyAlgorithm : sshPublicKey.getSshKeyAlgorithms()) {
                sshKeyImplementations.put(keyAlgorithm, sshPublicKey.getClass());
            }
            publicKeyImplementations.put(sshPublicKey.getKeyAlgorithm(), sshPublicKey.getClass());
        }
    }

    /**
     * Creates an SshPublicKey based on a standard java public key
     *
     * @param publicKey a standard public key
     * @return a SshPublicKey
     */
    public SshPublicKey getSshPublicKey(final PublicKey publicKey) {
        try {
            SshPublicKey result = publicKeyImplementations.get(publicKey.getAlgorithm()).getConstructor().newInstance();
            result.setPublicKey(publicKey);
            return result;
        } catch (InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException
                | SecurityException e) {
            throw new IllegalStateException(
                    "Could not instance class of type " + publicKeyImplementations.get(publicKey.getAlgorithm()).getCanonicalName(), e);
        }
    }

    /**
     * Decodes an SSH public key
     *
     * @param publicKey the SSH public key body, not including the prefix and comment.
     * @return an a SshPublicKey
     * @throws SshKeyException if the key was not a proper SSH key
     * @throws InvalidKeySpecException if the key body could not be parsed
     */
    public SshPublicKey getSshPublicKey(final byte[] publicKey) throws InvalidKeySpecException, SshKeyException {
        SshCertificateReader sshCertificateReader = new SshCertificateReader(publicKey);
        String algorithm;
        try {
            algorithm = sshCertificateReader.readString();
        } catch (IOException e) {
            throw new SshKeyException(e);
        } finally {
            sshCertificateReader.close();
        }

        try {
            SshPublicKey result = sshKeyImplementations.get(algorithm).getConstructor().newInstance();
            result.init(publicKey);
            return result;
        } catch (InvocationTargetException | NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException
                | IllegalArgumentException e) {
            throw new IllegalStateException("Could not instance class of type " + sshKeyImplementations.get(algorithm).getCanonicalName(), e);
        }
    }
    
    /**
     * Decodes an SSH public key from a file after trimming
     *
     * @param publicKeyFile the SSH public key body, trims the prefix and comment.
     * @return an a SshPublicKey
     * @throws SshKeyException if the key was not a proper SSH key
     * @throws InvalidKeySpecException if the key body could not be parsed
     */
    public SshPublicKey extractSshPublicKeyFromFile(final byte[] publicKeyFile) 
                        throws InvalidKeySpecException, SshKeyException {
        String publicKeyFileContent = new String(publicKeyFile);
        
        int prefixIndex = publicKeyFileContent.indexOf(" ");
        if(prefixIndex==-1) {
            throw new IllegalStateException("SSH pubkey file content is malformed: does not contain perifx or algorithm");
        }
        
        String algorithm = publicKeyFileContent.substring(0, prefixIndex).trim();
        int suffixIndex = publicKeyFileContent.indexOf(" ", prefixIndex+1);
        if(suffixIndex==-1) {
            publicKeyFileContent = publicKeyFileContent.substring(prefixIndex+1);
        } else {
            publicKeyFileContent = publicKeyFileContent.substring(prefixIndex+1, suffixIndex);
        }
        
        try {
            SshPublicKey result = sshKeyImplementations.get(algorithm).getConstructor().newInstance();
            result.init(Base64.decode(publicKeyFileContent.getBytes()));
            return result;
        } catch (InvocationTargetException | NoSuchMethodException | SecurityException | InstantiationException | IllegalAccessException
                | IllegalArgumentException e) {
            throw new IllegalStateException("Could not instance class of type " + sshKeyImplementations.get(algorithm).getCanonicalName(), e);
        }
    }
    
    public static String getSshKeyType(Key sshAuthKey) {
        String keyAlgorithm = sshAuthKey.getAlgorithm().toLowerCase();
        if (keyAlgorithm.contains("rsa")) {
            return "ssh-rsa";
        } else if (keyAlgorithm.contains("ec")) {
            ECPublicKey ecPubKey = (ECPublicKey) sshAuthKey;
            int fieldSize = ecPubKey.getParams().getCurve().getField().getFieldSize();
            if (fieldSize==256 || fieldSize==384 || fieldSize==521) {
                return "ecdsa-sha2-nistp" + fieldSize;
            } else {
                throw new IllegalArgumentException("Invalid EC public key for auth. "
                        + "Only ECDSA (256, 384, 521) bit keys are allowed.");
            }
        } else if (keyAlgorithm.contains("ed25519")) {
            return "ssh-ed25519";
        } else {
            throw new IllegalArgumentException("Invalid public key for auth. "
                    + "Only RSA, ED25519 and ECDSA (256, 384, 521) keys are allowed.");
        }
    }
    
    public static byte[] makePublicKeyBlob(Key sshAuthKey) {
        
        String keyAlgorithm = sshAuthKey.getAlgorithm().toLowerCase();
        String sshKeyType = getSshKeyType(sshAuthKey);        
        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
            sshCertificateWriter.writeString(sshKeyType);
            if (keyAlgorithm.contains("rsa")) {
                RSAPublicKey rsaPubKey = (RSAPublicKey) sshAuthKey;
                sshCertificateWriter.writeBigInteger(rsaPubKey.getPublicExponent());
                sshCertificateWriter.writeBigInteger(rsaPubKey.getModulus());
            } else if (keyAlgorithm.contains("ec")) {
                ECPublicKey ecPubKey = (ECPublicKey) sshAuthKey;
                sshCertificateWriter.writeString("nistp" + ecPubKey.getParams().getCurve().getField().getFieldSize());
                sshCertificateWriter.writeByteArray(KeyTools.encodeEcPoint(ecPubKey.getW(), ecPubKey.getParams().getCurve()));
            } else if (keyAlgorithm.contains("ed25519")) {
                sshCertificateWriter.writeByteArray(KeyTools.encodeEd25519PublicKey((PublicKey) sshAuthKey));
            }
            sshCertificateWriter.flush();
            sshCertificateWriter.close();
            return sshCertificateWriter.toByteArray();
        } catch (IOException e) {
            throw new IllegalStateException("Unable to encode public key blob", e);
        }
        
    }
    
    public static String getDownloadableSshKey(Key sshAuthKey) {
        String sshKeyType = getSshKeyType(sshAuthKey);        
        String result = sshKeyType + " ";
        result += new String(Base64.encode(makePublicKeyBlob(sshAuthKey)), StandardCharsets.UTF_8);
        return result;
      }
}
