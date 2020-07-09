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

package org.ejbca.core.protocol.ssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.keys.util.KeyTools;

/**
 * 
 * @version $Id$
 *
 */
public class SshRequestMessage implements RequestMessage {

    private static final long serialVersionUID = 1L;
    
    private final String keyId;
    private final String comment;
    private final byte[] publicKey;
    private final List<String> principals;
    private final Map<String, String> criticalOptions;
    private final Map<String, byte[]> additionalExtensions;
    private String username;
    
    
    private transient String serialNumber;
    private transient String password;


    public SshRequestMessage(final PublicKey publicKey, final String keyId, List<String> principals, final Map<String, byte[]> additionalExtensions,
            final Map<String, String> criticalOptions, final String comment) {
        this.keyId = keyId;
        this.comment = comment;
        this.publicKey = publicKey.getEncoded();
        this.principals = principals;
        this.criticalOptions = criticalOptions;
        this.additionalExtensions = additionalExtensions;
    }
    
    public SshRequestMessage(final byte[] publicKey, final String keyId, List<String> principals, final Map<String, byte[]> additionalExtensions,
            final Map<String, String> criticalOptions, final String comment) {
        this.keyId = keyId;
        this.comment = comment;
        this.publicKey = publicKey;
        this.principals = (principals != null ? principals : new ArrayList<>());
        this.criticalOptions = (criticalOptions != null ? criticalOptions : new HashMap<>());
        this.additionalExtensions = (additionalExtensions != null ? additionalExtensions : new HashMap<>());
    }
    
    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out;
        byte[] encodedObject;
        try {
            out = new ObjectOutputStream(bos);
            out.writeObject(this);
            out.flush();
            encodedObject = bos.toByteArray();
        } finally {
            try {
                bos.close();
            } catch (IOException ex) {
                // NOPMD: ignore close exception
            }
        }
        return encodedObject;
    }

    @Override
    public String getUsername() {
        return username;
    }

    public void setUsername(final String username) {
        this.username = username;
    }
    
    public void setPassword(final String password) {
        this.password = password;
    }
    
    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getSerialNo() {
        return null;
    }

    @Override
    public String getRequestDN() {
        return null;
    }

    @Override
    public X500Name getRequestX500Name() {
        return null;
    }

    @Override
    public String getRequestAltNames() {
        return null;
    }

    @Override
    public Date getRequestValidityNotBefore() {
        return null;
    }

    @Override
    public Date getRequestValidityNotAfter() {
        return null;
    }

    @Override
    public Extensions getRequestExtensions() {
        return null;
    }

    @Override
    public String getCRLIssuerDN() {
        return null;
    }

    @Override
    public BigInteger getCRLSerialNo() {
        return null;
    }

    @Override
    public PublicKey getRequestPublicKey() throws InvalidKeyException {
        //Key can either come in as a straight java public key or an SSH public key, we'll accept both. First try a standard public key.
        PublicKey result = KeyTools.getPublicKeyFromBytes(publicKey);
        if(result != null) {
            return result;
        } else {
            try {
                byte[] keyBody = new String(publicKey).split(" ")[1].getBytes();     
                SshPublicKey sshPublicKey = SshKeyFactory.INSTANCE.getSshPublicKey(Base64.decode(keyBody));
                return sshPublicKey.getPublicKey();
            } catch (InvalidKeySpecException | SshKeyException | ArrayIndexOutOfBoundsException e) {
               throw new InvalidKeyException(e);
            }
        }
    }

    @Override
    public boolean verify() {
        return true;
    }

    @Override
    public boolean requireKeyInfo() {
        return false;
    }

    @Override
    public void setKeyInfo(Certificate cert, PrivateKey key, String provider) {

    }

    @Override
    public int getErrorNo() {
        return 0;
    }

    @Override
    public String getErrorText() {
        return null;
    }

    @Override
    public String getSenderNonce() {
        return null;
    }

    @Override
    public String getTransactionId() {
        return null;
    }

    @Override
    public byte[] getRequestKeyInfo() {
        return null;
    }

    @Override
    public String getPreferredDigestAlg() {
        return null;
    }

    @Override
    public boolean includeCACert() {
        return false;
    }

    @Override
    public int getRequestType() {
        return 0;
    }

    @Override
    public int getRequestId() {
        return 0;
    }

    @Override
    public void setResponseKeyInfo(PrivateKey key, String provider) {

    }

    @Override
    public List<Certificate> getAdditionalCaCertificates() {
        return null;
    }

    @Override
    public void setAdditionalCaCertificates(List<Certificate> additionalCaCertificates) {

    }

    @Override
    public List<Certificate> getAdditionalExtraCertsCertificates() {
        return null;
    }

    @Override
    public void setAdditionalExtraCertsCertificates(List<Certificate> additionalExtraCertificates) {

    }
    
    
    public String getKeyId() {
        return keyId;
    }

    public String getComment() {
        return comment;
    }

    public Map<String, byte[]> getAdditionalExtensions() {
        return additionalExtensions;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public Map<String, String> getCriticalOptions() {
        return criticalOptions;
    }

    @Override
    public String getCASequence() {
        return null;
    }

}
