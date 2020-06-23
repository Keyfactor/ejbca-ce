/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.certificate;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

import org.cesecore.certificates.certificate.ssh.SshCertificate;
import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateType;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshKeyFactory;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;

/**
 * Base class for SSH certificates
 * 
 * 
 * Contents:
 *  In addition to the values derived from the respective public keys, the contents of an SSH certificate are as follows:
 *  https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
 * 
 *  82:     uint64    serial
 *  83:     uint32    type
 *  84:     string    key id
 *  85:     string    valid principals
 *  86:     uint64    valid after
 *  87:     uint64    valid before
 *  88:     string    critical options
 *  89:     string    extensions
 *  90:     string    reserved <-- Ignored
 *  91:     string    signature key
 *  92:     string    signature 
 * 
 * @version $Id$
 *
 */
public abstract class SshCertificateBase extends Certificate implements SshCertificate {

    private SshPublicKey publicKey;
    private byte[] nonce;
    private long serialNumber; // Treat as an unsigned long
    private SshCertificateType sshCertificateType;
    private String keyId;
    private Set<String> principals;
    private Date validAfter; // Treat as unsigned long
    private Date validBefore; // Treat as unsigned long
    private Map<String, String> criticalOptions;
    private Map<String, byte[]> extensions;
    private String reserved = null;
    private SshPublicKey signKey;
    private byte[] encodedSignature = null;
    private String comment;
    
    /**
     * Non-standard identifier for the issuing CA
     */
    private transient String issuerIdentifier;
    
    public SshCertificateBase() {
        super(CERTIFICATE_TYPE);
    }

    public SshCertificateBase(final SshPublicKey publicKey, byte[] nonce, final String serialNumber, final SshCertificateType sshCertificateType,
            final String keyId, final Set<String> principals, final Date validAfter, final Date validBefore,
            final Map<String, String> criticalOptions, final Map<String, byte[]> extensions, final SshPublicKey signKey, final String comment, final String issuerIdentifier) {
        super(CERTIFICATE_TYPE);
        this.publicKey = publicKey;
        this.nonce = nonce;
        this.serialNumber = Long.parseUnsignedLong(serialNumber);
        this.sshCertificateType = sshCertificateType;
        this.keyId = keyId;
        this.principals = principals;
        this.validAfter = validAfter;
        this.validBefore = validBefore;
        this.criticalOptions = criticalOptions != null ? criticalOptions : new HashMap<String, String>();
        
        if(SshCertificateType.USER.getType() == sshCertificateType.getType() && extensions != null) {
            this.extensions = extensions;
        } else {
            //No extensions are defined for host certificates, so ignore. 
            this.extensions = new TreeMap<>();
        }        
        this.signKey = signKey;
        this.comment = comment;
        this.issuerIdentifier = issuerIdentifier;
    }
    
    @Override
    public abstract void init(final byte[] encodedCertificate) throws CertificateEncodingException, SshKeyException;
    
    /**
     * Decodes the rest of the certificate body that belongs to the base class. 
     * 
     * @param sshCertificateReader an {@link SshCertificateReader}
     * @throws IOException if the content of the certificate reader couldn't be read
     * @throws SshKeyException if the signing key could not be read
     * @throws InvalidKeySpecException 
     */
    protected void init(final SshCertificateReader sshCertificateReader) throws IOException, InvalidKeySpecException, SshKeyException {
        this.serialNumber = sshCertificateReader.readLong();
        this.sshCertificateType = SshCertificateType.fromInt(new Long(sshCertificateReader.readInt()).intValue());
        this.keyId = sshCertificateReader.readString();
        byte[] principalsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader principalReader = new SshCertificateReader(principalsBytes);
        try {
            Set<String> principals = new HashSet<>();
            while (principalReader.available() > 0) {
                principals.add(principalReader.readString());
            }
            this.principals = principals;
        } finally {
            principalReader.close();
        }
        this.validAfter = new Date(sshCertificateReader.readLong()*1000);
        this.validBefore = new Date(sshCertificateReader.readLong()*1000);
        byte[] optionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader optionsReader = new SshCertificateReader(optionsBytes);
        Map<String, String> options = new HashMap<>();
        while (optionsReader.available() > 0) {
            String optionName = optionsReader.readString();
            //Value will be coded as a set of Strings
            byte[] optionValue = optionsReader.readByteArray();
            SshCertificateReader optionReader = new SshCertificateReader(optionValue);
            String optionList = "";
            while (optionReader.available() > 0) {
                optionList += optionReader.readString();
                if (optionReader.available() > 0) {
                    optionList += ",";
                }
            }
            optionReader.close();
            options.put(optionName, optionList);
        }
        optionsReader.close();
        this.criticalOptions = options;
        Map<String, byte[]> extensions = new TreeMap<>();
        byte[] extensionsBytes = sshCertificateReader.readByteArray();
        SshCertificateReader extensionsReader = new SshCertificateReader(extensionsBytes);
        while (extensionsReader.available() > 0) {
            String extensionKey = extensionsReader.readString();
            SshCertificateReader extensionValueReader = new SshCertificateReader(extensionsReader.readByteArray());
            byte[] extensionValue;
            if (extensionValueReader.available() > 0) {
                extensionValue = extensionValueReader.readByteArray();
            } else {
                extensionValue = "".getBytes();
            }
            extensionValueReader.close();
            extensions.put(extensionKey, extensionValue);
        }
        extensionsReader.close();
        this.extensions = extensions;
        this.reserved = sshCertificateReader.readString();
        byte[] signKeyBytes = sshCertificateReader.readByteArray();
        this.signKey = SshKeyFactory.INSTANCE.getSshPublicKey(signKeyBytes);
        this.encodedSignature = sshCertificateReader.readByteArray();        
    }

    /**
     * @return the String prefix for this certificate
     */
    protected abstract String getCertificatePrefix();

    /**
     * Writes the contents of this certificate, minus the signature which is based on the results of this method.
     * 
     * @param sshCertificateWriter a SshCertificateWriter
     * @throws IOException if any encoding errors occurred
     */
    protected void getEncoded(SshCertificateWriter sshCertificateWriter) throws IOException {
        sshCertificateWriter.writeLong(serialNumber);
        sshCertificateWriter.writeInt(sshCertificateType.getType());
        sshCertificateWriter.writeString(keyId);
        //Write principals in their own enclosed structure
        SshCertificateWriter principalsWriter = new SshCertificateWriter();
        for (String user : principals) {
            principalsWriter.writeString(user);
        }
        sshCertificateWriter.writeByteArray(principalsWriter.toByteArray());
        principalsWriter.flush();
        principalsWriter.close();
        sshCertificateWriter.writeLong(validAfter.getTime()/1000L);
        sshCertificateWriter.writeLong(validBefore.getTime()/1000L);
        //Critical Options are written in their own enclosed structure
        SshCertificateWriter criticalOptionsWriter = new SshCertificateWriter();
        for (String option : criticalOptions.keySet()) {
            criticalOptionsWriter.writeString(option);
            //Each option can also be a comma separated list, so that goes into its own structure.
            SshCertificateWriter optionWriter = new SshCertificateWriter();
            for (String optionValue : criticalOptions.get(option).split(",")) {
                optionWriter.writeString(optionValue);
            }
            criticalOptionsWriter.writeByteArray(optionWriter.toByteArray());
            optionWriter.flush();
            optionWriter.close();
        }
        sshCertificateWriter.writeByteArray(criticalOptionsWriter.toByteArray());
        criticalOptionsWriter.flush();
        criticalOptionsWriter.close();

        //Extensions are written in their own enclosed structure
        SshCertificateWriter extensionsWriter = new SshCertificateWriter();
        for (String extensionKey : extensions.keySet()) {
            extensionsWriter.writeString(extensionKey);
            byte[] extensionValue = extensions.get(extensionKey);
            if (extensionValue.length > 0) {
                SshCertificateWriter extensionValueWriter = new SshCertificateWriter();
                extensionValueWriter.writeByteArray(extensions.get(extensionKey));
                extensionsWriter.writeByteArray(extensionValueWriter.toByteArray());
                extensionValueWriter.flush();
                extensionValueWriter.close();
            } else {
                extensionsWriter.writeByteArray(new byte[0]);
            }
        }      
        sshCertificateWriter.writeByteArray(extensionsWriter.toByteArray());
        extensionsWriter.flush();
        extensionsWriter.close();

        sshCertificateWriter.writeString(reserved); //Not used
        sshCertificateWriter.writeByteArray(signKey.encode());
    }

    @Override
    public void verify(PublicKey key)
            throws CertificateException, InvalidKeyException, SignatureException {
        if (!verify()) {
            throw new SignatureException("Signature verification failed.");
        }
    }

    @Override
    public void verify(PublicKey key, String sigProvider)
            throws CertificateException, NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException, SignatureException {
        if (!verify()) {
            throw new SignatureException("Signature verification failed.");
        }
    }

    @Override
    public abstract byte[] encodeCertificateBody() throws CertificateEncodingException;

    /**
     * Verifies the signature on this certificate. The other two verification methods will lead here as well, ignoring their respective 
     * parameters, as the signing key is incorporated into this certificate type.
     * 
     * @return true if the the signature in this certificate verified according to the included signing key
     * @throws InvalidKeyException if the signature key in this certificate was invalid
     * @throws CertificateEncodingException if the data body of this certificate couldn't be encoded
     * @throws SignatureException
     */
    @Override
    public boolean verify() throws SignatureException, InvalidKeyException, CertificateEncodingException {
        //The signature can be by any key and algorithm type, but can be divined from the signature body.
        SshCertificateReader signatureReader = new SshCertificateReader(encodedSignature);
        String signatureAlgorithm;
        byte[] signatureBytes;
        try {
            signatureAlgorithm = signatureReader.readString();
            signatureBytes = signatureReader.readByteArray();
        } catch (IOException e) {
            throw new SignatureException("Could not parse signature body", e);
        } finally {
            signatureReader.close();
        }

        //The data body is the complete certificate, except the signature
        byte[] data = encodeCertificateBody();

        return verifySignature(signatureAlgorithm, signatureBytes, data);
    }

    /**
     * 
     * @param signatureAlgorithm a signature algorithm
     * @return a Signature object based on the signature algorithm
     * @throws SignatureException 
     * @throws InvalidKeyException 
     */
    protected abstract boolean verifySignature(final String signatureAlgorithm, final byte[] signatureBytes, final byte[] data)
            throws InvalidKeyException, SignatureException;

    @Override
    public String toString() {
        // TODO SSH Implement ECA-9184
        return null;
    }

    @Override
    public byte[] getNonce() {
        return nonce;
    }

    @Override
    public PublicKey getPublicKey() {
        return publicKey.getPublicKey();
    }
    
    @Override
    public SshPublicKey getSshPublicKey() {
        return publicKey;
    }

    @Override
    public SshPublicKey getSigningKey() {
        return signKey;
    }

    @Override
    public SshCertificateType getSshCertificateType() {
        return this.sshCertificateType;
    }

    @Override
    public void setSignature(byte[] signature) {
        this.encodedSignature = signature;
    }
    
    @Override
    public byte[] getSignature() {
        return encodedSignature;
    }

    @Override
    public String getComment() {
        return comment;
    }

    @Override
    public long getSerialNumber() {
        return serialNumber;
    }
    
    @Override
    public String getSerialNumberAsString() {
        return Long.toUnsignedString(serialNumber);
    }
    
    @Override
    public String getIssuerIdentifier() {
        return issuerIdentifier;
    }

    @Override
    public void setComment(String comment) {
        this.comment = comment;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public void setPublicKey(SshPublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
