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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.keys.token.CryptoTokenSessionLocal;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.util.EjbLocalHelper;

import com.jcraft.jsch.Identity;
import com.jcraft.jsch.JSchException;
import com.keyfactor.util.Base64;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.CryptoTokenOfflineException;

public class ScpPublisherIdentity implements Identity  {
    
    private static final Logger log = Logger.getLogger(ScpPublisherIdentity.class);
    
    private static final Map<String, String> sshAlgoNameToBcSignAlgoName = new HashMap<>();
    
    static {
        sshAlgoNameToBcSignAlgoName.put("rsa-sha2-256", "SHA256withRSA");
        sshAlgoNameToBcSignAlgoName.put("rsa-sha2-512", "SHA512withRSA");
        
        sshAlgoNameToBcSignAlgoName.put("ssh-ed25519", "Ed25519");
        
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp256", "SHA256withECDSA");
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp384", "SHA384withECDSA");
        sshAlgoNameToBcSignAlgoName.put("ecdsa-sha2-nistp521", "SHA512withECDSA");
    }
    
    private int cryptotokenId;
    private String keyPairName;
    private String keyAlgorithm;
    private byte[] publicKeyBlob;
    
    public ScpPublisherIdentity(int cryptotokenId, String keyPairName, 
            String keyAlgorithm, Key sshAuthKey) throws PublisherException {
        
        if (log.isDebugEnabled()) {
            log.debug("Creating ScpPublisherIdentity: " + cryptotokenId + " : " + keyPairName + " : " + keyAlgorithm);
        }
        this.cryptotokenId = cryptotokenId;
        this.keyPairName = keyPairName;
        this.keyAlgorithm = SshKeyFactory.getSshKeyType(sshAuthKey);
        this.publicKeyBlob = SshKeyFactory.makePublicKeyBlob(sshAuthKey);
    }
    
    

    @Override
    public boolean setPassphrase(byte[] passphrase) throws JSchException {
        return true;
    }

    @Override
    public byte[] getPublicKeyBlob() {
        if (log.isDebugEnabled()) {
            log.debug("getPublicKeyBlob alg: " + new String(Base64.encode(publicKeyBlob)));
        }
        return publicKeyBlob;
    }

    @Override
    public byte[] getSignature(byte[] data) {
        return getSignature(data, "SHA256withRSA");
    }
    
    @Override
    public byte[] getSignature(byte[] data, String alg) {
        String signatureAlgorithm = sshAlgoNameToBcSignAlgoName.get(alg);
        CryptoTokenSessionLocal cryptoTokenSessionLocal = new EjbLocalHelper().getCryptoTokenSession();
        CryptoToken cryptoToken = cryptoTokenSessionLocal.getCryptoToken(cryptotokenId);
        String providerName = cryptoToken.getSignProviderName();
        log.debug("providerName: " + providerName);
        
        Signature sig;
        try {
            sig = Signature.getInstance(signatureAlgorithm, providerName);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("Provider could not be loaded: " + providerName, e);
        }
        
        byte[] sign;
        try {
            sig.initSign(cryptoToken.getPrivateKey(keyPairName));
            sig.update(data);
            sign = sig.sign();
        } catch (InvalidKeyException | CryptoTokenOfflineException | SignatureException e) {
            log.info("SSH authentication could not be done using cryptotokenId: " 
                            + cryptotokenId + ", keypair: " + keyPairName + ", algorithm: " + alg, e);
            throw new IllegalStateException(e);
        }
        
        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
            sshCertificateWriter.writeString(alg);
            if (alg.contains("ecdsa")) {
                ByteArrayInputStream inStream = new ByteArrayInputStream(sign);
                ASN1InputStream asnInputStream = new ASN1InputStream(inStream);
                ASN1Sequence asn1Sequence = (ASN1Sequence) asnInputStream.readObject();
                ASN1Encodable[] asn1Encodables = asn1Sequence.toArray();
                SshCertificateWriter signatureWriter = new SshCertificateWriter();
                for (ASN1Encodable asn1Encodable : asn1Encodables) {
                    ASN1Integer asn1Integer = (ASN1Integer) asn1Encodable.toASN1Primitive();
                    BigInteger integer = asn1Integer.getValue();
                    signatureWriter.writeBigInteger(integer);
                }
                asnInputStream.close();
                sshCertificateWriter.writeByteArray(signatureWriter.toByteArray());
                signatureWriter.close();
            } else {
                sshCertificateWriter.writeByteArray(sign);
            }

            sshCertificateWriter.flush();
            sshCertificateWriter.close();

        } catch (IOException e) {
            throw new IllegalStateException("Could not convert to SSH signature", e);
        }
        return sshCertificateWriter.toByteArray();
    }

    @Override
    public String getAlgName() {
        log.debug("keyAlgorithm: " + keyAlgorithm);
        return this.keyAlgorithm;
    }

    @Override
    public String getName() {
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
