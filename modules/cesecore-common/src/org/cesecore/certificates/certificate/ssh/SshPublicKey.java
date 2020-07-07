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
import java.io.Serializable;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.cesecore.certificates.util.AlgorithmConstants;

/**
 * Marker interface for SSH Public Keys
 *
 * @version $Id$
 */
public interface SshPublicKey extends Serializable {

    List<String> availableKeyAlgorithms = Collections.unmodifiableList(Arrays.asList(AlgorithmConstants.KEYALGORITHM_ECDSA,
            AlgorithmConstants.KEYALGORITHM_RSA, AlgorithmConstants.KEYALGORITHM_ED25519, AlgorithmConstants.KEYALGORITHM_ED448));

    /**
     * Initializes this public key based on the key body from an encoded certificate
     *
     * @param keyBody an encoded key body
     * @throws SshKeyException if the key was not a proper SSH key
     * @throws InvalidKeySpecException if the key body could not be parsed
     */
    void init(final byte[] keyBody) throws SshKeyException, InvalidKeySpecException;

    String getKeyAlgorithm();

    List<String> getSshKeyAlgorithms();

    void setPublicKey(final PublicKey publicKey);

    PublicKey getPublicKey();

    /**
     * Encodes the contents of this public key
     *
     * @return a byte array of the contents of this public key, including SSH-appropriate prefix
     * @throws IOException if any failure happened during the encoding process
     */
    byte[] encode() throws IOException;

    /**
     * Encodes this public key for export as an SSH Public Key
     *
     * @param comment any comment to add
     * @return the public key exported as a byte array
     * @throws IOException if any failure happened during the encoding process
     */
    byte[] encodeForExport(String comment) throws IOException;

}
