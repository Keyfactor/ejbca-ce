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
import java.security.cert.Certificate;
import java.util.LinkedHashMap;

/**
 * Interface for the InternalKeyBindings.
 * @version $Id$
 */
public interface InternalKeyBinding extends Serializable {

    /** Called directly after implementation instantiation status */
    void init(int id, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, LinkedHashMap<Object, Object> dataMapToLoad);

    /** Called directly before object is persisted */
    LinkedHashMap<Object, Object> getDataMapToPersist();
    
    /** Return the non-changeable alias for this implementation. E.g. "DummyKeyBinding". */
    String getImplementationAlias();
    
    /** @return the next key pair's alias t be used */
    String getNextKeyPairAlias();

    /** Uses the next key alias as current key alias and updates the certificateId */
    void updateCertificateIdAndCurrentKeyAlias(String certificateId);

    /** Generates a next key pair alias based on the current one using a simple counter as postfix */
    void generateNextKeyPairAlias();

    /**
     * IMPORTANT: The validation must be done properly to avoid unintended certificate import.
     * 
     * @throws CertificateImportException if the provided certificate is not compatible with this type of implementation
     */
    void assertCertificateCompatability(Certificate certificate) throws CertificateImportException;

    /** @return the non-changeable id of this instance */
    int getId();

    /** @return the current human friendly name of this instance */
    String getName();
    /** Sets the current human friendly name of this instance */
    void setName(String name);

    /** @return the current status of this instance */
    InternalKeyBindingStatus getStatus();
    /** Sets the current status of this instance */
    void setStatus(InternalKeyBindingStatus status);

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
