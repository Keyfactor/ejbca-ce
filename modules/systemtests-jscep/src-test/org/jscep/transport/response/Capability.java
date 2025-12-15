/*
 * Copyright (c) 2009-2010 David Grant
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jscep.transport.response;

import org.jscep.transport.request.GetNextCaCertRequest;
import org.jscep.transport.request.PkiOperationRequest;

/**
 * This class represents a single SCEP server capability.
 * 
 * @author David Grant
 */
public enum Capability {
    /**
     * CA supports the AES encryption algorithm.
     */
    AES("AES", "AES Encryption"),
    /**
     * CA Supports the GetNextCACert message.
     * 
     * @see GetNextCaCertRequest
     */
    GET_NEXT_CA_CERT("GetNextCACert", "Certificate Rollover"),
    /**
     * PKIOperation messages may be sent via HTTP POST.
     * 
     * @see PkiOperationRequest
     */
    POST_PKI_OPERATION("POSTPKIOperation", "HTTP POST"),
    /**
     * Clients may use current certificate and key to authenticate an enrollment
     * request for a new certificate.
     */
    RENEWAL("Renewal", "Certificate Renewal"),
    /**
     * CA supports all mandatory-to-implement sections of the SCEP standard.
     * This keyword implies "AES", "POSTPKIOperation", and "SHA-256".
     */
    SCEP_STANDARD("SCEPStandard", "SCEP Standard"),
    /**
     * CA Supports the SHA-512 hashing algorithm in signatures and fingerprints.
     */
    SHA_512("SHA-512", "SHA-512 Message Digest"),
    /**
     * CA Supports the SHA-256 hashing algorithm in signatures and fingerprints.
     */
    SHA_256("SHA-256", "SHA-256 Message Digest"),
    /**
     * CA Supports the SHA-1 hashing algorithm in signatures and fingerprints.
     */
    SHA_1("SHA-1", "SHA-1 Message Digest"),
    /**
     * CA Supports triple-DES for encryption.
     */
    TRIPLE_DES("DES3", "Triple DES Encryption"),
    /**
     * CA supports the Update CA operation.
     */
    UPDATE("Update", "Certificate Update");

    /**
     * Member variable to hold the name of the capability as defined in the SCEP
     * Internet-Draft.
     */
    private final String capability;
    private final String description;

    /**
     * Constructs a new instance of this enum.
     * 
     * @param capability
     *            the name of the capability.
     * @param description
     *            description of the capability
     */
    private Capability(final String capability, final String description) {
        this.capability = capability;
        this.description = description;
    }

    /**
     * Returns the name of the capability as defined in the SCEP Internet-Draft.
     * 
     * @return the name of the capability.
     */
    @Override
    public String toString() {
        return capability;
    }

    /**
     * Returns the textual description of a this capability.
     * <p>
     * The value returned by this method is useful for using in logging
     * messages.
     * 
     * @return thet textual description of this capability.
     */
    public String getDescription() {
        return description;
    }
}
