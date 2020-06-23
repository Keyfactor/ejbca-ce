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

import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.util.List;

/**
 * Base interface for SSH certificates
 * 
 * @version $Id$
 *
 */

public interface SshCertificate {

    String CERTIFICATE_TYPE = "SSH";
    String CRITICAL_OPTION_FORCE_COMMAND = "force-command";
    String CRITICAL_OPTION_SOURCE_ADDRESS = "source-address";

    /**
     * Encodes the certificte body of this certificate, minus the signature
     * 
     * @return a byte array containing the certificate body
     * @throws CertificateEncodingException if the certificate couldn't be encoded
     */
    byte[] encodeCertificateBody() throws CertificateEncodingException;

    /**
     * Verifies the signature on this certificate. The other two verification methods will lead here as well, ignoring their respective 
     * parameters, as the signing key is incorporated into this certificate type.
     * 
     * @return true if the the signature in this certificate verified according to the included signing key
     * @throws InvalidKeyException if the signature key in this certificate was invalid
     * @throws CertificateEncodingException if the data body of this certificate couldn't be encoded
     * @throws SignatureException
     */
    boolean verify() throws SignatureException, InvalidKeyException, CertificateEncodingException;

    String toString();

    byte[] getNonce();

    PublicKey getPublicKey();

    SshPublicKey getSshPublicKey();

    SshPublicKey getSigningKey();

    SshCertificateType getSshCertificateType();

    void setSignature(byte[] signature);

    byte[] getSignature();

    String getComment();

    long getSerialNumber();

    String getSerialNumberAsString();
    
    /**
     * Non standard field for identifying the issuing CA
     * 
     * @return the issuer identifier
     */
    String getIssuerIdentifier();
    
    /**
     * 
     * @return the implementation type of this certificate
     */
    List<String> getCertificateImplementations();

    void setComment(String comment);
    
    /**
     * Decodes this certificate from a byte array
     * 
     * @param encodedCertificate an SSH encoded certificate
     * @throws CertificateEncodingException if the certificate was incorrectly encoded
     * @throws SshKeyException if the public key could not be read
     */
    void init(byte[] encodedCertificate) throws CertificateEncodingException, SshKeyException;

}