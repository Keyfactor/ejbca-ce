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
package org.ejbca.core.ejb.signer;

import java.io.Serializable;
import java.util.LinkedHashMap;

/**
 * Interface for the SignerMappings.
 * @version $Id$
 */
public interface SignerMapping extends Serializable {

    /** Called directly after implementation instantiation status */
    void init(int signerId, String name, SignerMappingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, LinkedHashMap<Object, Object> dataMapToLoad);

    /** Called directly before object is persisted */
    LinkedHashMap<Object, Object> getDataMapToPersist();
    
    /** Return the non-changeable alias for this implementation. E.g. "DummySignerMapping". */
    String getSignerMappingAlias();
    
    /**
     * IMPORTANT: The validation must be done properly to avoid unintended certificate import.
     * 
     * @throws CertificateImportException if the provided certificate is not compatible with this type of SignerMapping
     */
    void assertCertificateCompatability(byte[] derEncodedCertificate) throws CertificateImportException;

    /** @return the non-changeable id of this SignerMapping */
    int getId();

    /** @return the current human friendly name of this SignerMapping */
    String getName();
    /** Sets the current human friendly name of this SignerMapping */
    void setName(String name);

    /** @return the current human friendly name of this SignerMapping */
    SignerMappingStatus getStatus();
    /** Sets the current human friendly name of this SignerMapping */
    void setStatus(SignerMappingStatus status);

    /** @return the fingerprint of the certificate currently in use or null if none is referenced */
    String getCertificateId();
    /** Sets the fingerprint of the certificate currently in use */
    void setCertificateId(String certificateId);

    /** @return the id of the CryptoToken currently in use */
    int getCryptoTokenId();
    /** Sets the id of the CryptoToken currently in use */
    void setCryptoTokenId(int cryptoTokenId);

    /** @return the key pair alias currently in use */
    String getKeyPairAlias();
    /** Sets the key pair alias currently in use */
    void setKeyPairAlias(String keyPairAlias);

}
