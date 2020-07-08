/*************************************************************************
 *                                                                       *
 *  EJBCA - Proprietary Modules: Enterprise Certificate Authority        *
 *                                                                       *
 *  Copyright (c), PrimeKey Solutions AB. All rights reserved.           *
 *  The use of the Proprietary Modules are subject to specific           * 
 *  commercial license terms.                                            *
 *                                                                       *
 *************************************************************************/
package org.ejbca.ssh.keys.rsa;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Collections;
import java.util.List;

import org.cesecore.certificates.certificate.ssh.SshCertificateReader;
import org.cesecore.certificates.certificate.ssh.SshCertificateWriter;
import org.cesecore.certificates.certificate.ssh.SshKeyException;
import org.cesecore.certificates.certificate.ssh.SshPublicKey;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.util.Base64;

/**
 * SSH RSA Public Key.
 *
 * @version $Id$
 */
public class SshRsaPublicKey implements SshPublicKey {
    public static final String SSH_RSA = "ssh-rsa";
    public static final String SSH_RSA2_SHA256 = "rsa-sha2-256";
    public static final String SSH_RSA2_SHA512 = "rsa-sha2-512";

    private static final long serialVersionUID = 1L;

    private RSAPublicKey rsaPublicKey;

    /**
     * Required by service locator
     */
    public SshRsaPublicKey() {
        rsaPublicKey = null;
    }

    public SshRsaPublicKey(RSAPublicKey rsaPublicKey) {
      this.rsaPublicKey = rsaPublicKey;
    }

    /**
     * Read an RSA public key encoded in SSH format
     *
     * @param encodedBytes a byte array containing the public key, in the format: <br/>
     *  * String algorithm
     *  * BigInteger modulus
     *  * BigInteger exponent
     * @throws SshKeyException if the key was not an RSA key, or the encoded array could not be read.
     * @throws InvalidKeySpecException if the exponent of modulus were invalid
     */
    public SshRsaPublicKey(byte[] encodedBytes) throws SshKeyException, InvalidKeySpecException {
        init(encodedBytes);
    }

    @Override
    public void init(byte[] keyBody) throws SshKeyException, InvalidKeySpecException {
        try (SshCertificateReader sshCertificateReader = new SshCertificateReader(keyBody)) {
            String algorithm = sshCertificateReader.readString();
            if (!algorithm.equals(SSH_RSA)) {
                throw new SshKeyException("Endoded key was not prefixed with " + SSH_RSA + ", was " + algorithm + ".");
            }
            BigInteger publicExponent = sshCertificateReader.readBigInteger();
            BigInteger modulus = sshCertificateReader.readBigInteger();

            RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, publicExponent);
            KeyFactory keyFactory;
            try {
                keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(AlgorithmConstants.KEYALGORITHM_RSA + " was not a valid algorithm.", e);
            }
            this.rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
        } catch (IOException e) {
            throw new SshKeyException("Could not read encoded key.", e);
        }
    }

    public SshRsaPublicKey(BigInteger modulus, BigInteger exponent) throws InvalidKeySpecException {
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory keyFactory;
        try {
            keyFactory = KeyFactory.getInstance(AlgorithmConstants.KEYALGORITHM_RSA);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(AlgorithmConstants.KEYALGORITHM_RSA + " was not a valid algorithm.", e);
        }
        this.rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(rsaPublicKeySpec);
    }

    public String getAlgorithm() {
      return this.rsaPublicKey.getAlgorithm();
    }

    public String getFormat() {
      return this.rsaPublicKey.getFormat();
    }

    @Override
    public byte[] encode() throws IOException {

        SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
        try {
          sshCertificateWriter.writeString(SSH_RSA);
          sshCertificateWriter.writeBigInteger(this.rsaPublicKey.getPublicExponent());
          sshCertificateWriter.writeBigInteger(this.rsaPublicKey.getModulus());
        } finally {
          sshCertificateWriter.flush();
          sshCertificateWriter.close();
        }

        return sshCertificateWriter.toByteArray();
    }

    @Override
    public byte[] encodeForExport(String comment) throws IOException {
      String result = SSH_RSA + " ";
      SshCertificateWriter sshCertificateWriter = new SshCertificateWriter();
      try {
          sshCertificateWriter.writeByteArray(encode());
        } finally {
          sshCertificateWriter.flush();
          sshCertificateWriter.close();
        }
      result += new String(Base64.encode(encode(), false), StandardCharsets.UTF_8);
      if (comment != null && comment.trim().length() > 0) {
        result += " " + comment;
      }
      return result.getBytes();
    }

    public BigInteger getModulus() {
      return this.rsaPublicKey.getModulus();
    }

    public BigInteger getPublicExponent() {
      return this.rsaPublicKey.getPublicExponent();
    }

    @Override
    public String getKeyAlgorithm() {
        return AlgorithmConstants.KEYALGORITHM_RSA;
    }

    @Override
    public List<String> getSshKeyAlgorithms() {
        return Collections.singletonList(SSH_RSA);
    }

    public void setRsaPublicKey(RSAPublicKey rsaPublicKey) {
        this.rsaPublicKey = rsaPublicKey;
    }

    @Override
    public void setPublicKey(PublicKey publicKey) {
        setRsaPublicKey((RSAPublicKey) publicKey);
    }

    @Override
    public PublicKey getPublicKey() {
        return rsaPublicKey;
    }

  }
