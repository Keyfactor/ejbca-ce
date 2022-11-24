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
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import java.util.ServiceLoader;

import org.bouncycastle.util.encoders.Base64;

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
}
