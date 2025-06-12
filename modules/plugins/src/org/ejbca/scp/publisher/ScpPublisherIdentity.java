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
package org.ejbca.scp.publisher;

import java.io.IOException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.util.EjbLocalHelper;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSchException;
//import com.jcraft.jsch.MyBuffer;
import com.keyfactor.util.Base64;
import com.keyfactor.util.keys.token.CryptoToken;

public class ScpPublisherIdentity implements Identity  {
    
    private static final Logger log = Logger.getLogger(ScpPublisherIdentity.class);
    
    private static Map<String, String> sshAlgoNameToBcSignAlgoName = new HashMap<>();
    
    static {
        sshAlgoNameToBcSignAlgoName.put("rsa-sha2-256", "SHA256withRSA");
        sshAlgoNameToBcSignAlgoName.put("rsa-sha2-512", "SHA512withRSA");
        
        sshAlgoNameToBcSignAlgoName.put("ssh-ed25519", "Ed25519");
        
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp256", "SHA256withECDSA");
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp384", "SHA384withECDSA");
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp521", "SHA521withECDSA");
    }
    
    private int cryptotokenId;
    private String keyPairName;
    private String keyAlgorithm;
    //private PublicKey publicKey;
    private byte[] publicKeyBlob;
    
    public ScpPublisherIdentity(int cryptotokenId, String keyPairName, 
            String keyAlgorithm, Key sshAuthKey) throws PublisherException {
        
        log.info(cryptotokenId + " : " + keyPairName + " : " + keyAlgorithm);
        this.cryptotokenId = cryptotokenId;
        this.keyPairName = keyPairName;
        this.keyAlgorithm = SshKeyFactory.getSshKeyType(sshAuthKey);
        //this.publicKey = (PublicKey) sshAuthKey;
        // ssh-ed25519,ecdsa-sha2-nistp256
        
        //TODO: publicKeyBlob
        this.publicKeyBlob = SshKeyFactory.makePublicKeyBlob(sshAuthKey);
    }
    
    

    @Override
    public boolean setPassphrase(byte[] passphrase) throws JSchException {
        return true;
    }

    @Override
    public byte[] getPublicKeyBlob() {
        log.info("getPublicKeyBlob alg: " + new String(Base64.encode(publicKeyBlob)));
        return publicKeyBlob;
    }

    @Override
    public byte[] getSignature(byte[] data) {
        return getSignature(data, "SHA256withRSA");
    }
    
    @Override
    public byte[] getSignature(byte[] data, String alg) {
        log.info("getSignature alg: " + alg);
        log.info("getSignature data: " + new String(Base64.encode(data)));
        
        String signatureAlgorithm = sshAlgoNameToBcSignAlgoName.get(alg);
        log.info("signatureAlgorithm alg: " + signatureAlgorithm);
        CryptoTokenSessionLocal cryptoTokenSessionLocal = new EjbLocalHelper().getCryptoTokenSession();
        CryptoToken cryptoToken = cryptoTokenSessionLocal.getCryptoToken(cryptotokenId);
        String providerName = cryptoToken.getSignProviderName();
        
        Signature sig;
        try {
            sig = Signature.getInstance(signatureAlgorithm, providerName);
        } catch (NoSuchAlgorithmException e) {
            // TODO Auto-generated catch block
            throw new IllegalStateException(e);
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            throw new IllegalStateException(e);
        }
        
        byte[] sign = null;
        try {
            //sig.init();
            sig.initSign(cryptoToken.getPrivateKey(keyPairName));
            sig.update(data);
            sign = sig.sign();
        } catch (Exception e) {
            // TODO Auto-generated catch block
            throw new IllegalStateException(e);
        }
        
        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
            sshCertificateWriter.writeString(alg);
            sshCertificateWriter.writeByteArray(sign);

            sshCertificateWriter.flush();
            sshCertificateWriter.close();

        } catch (IOException e) {
            // TODO Auto-generated catch block
            throw new IllegalStateException(e);
        }
        byte[] formattedSign =  sshCertificateWriter.toByteArray(); 
        log.info("getSignature sign: " + new String(Base64.encode(formattedSign)));
        return formattedSign;
    }

    @Override
    public String getAlgName() {
        log.info("keyAlgorithm alg: " + keyAlgorithm);
        return this.keyAlgorithm;
    }

    @Override
    public String getName() {
        log.info("getName alg: " + cryptotokenId);
        return this.cryptotokenId + ":" + this.keyPairName;
    }

    @Override
    public boolean isEncrypted() {
        return false;
    }

    @Override
    public void clear() {        
    }

}
