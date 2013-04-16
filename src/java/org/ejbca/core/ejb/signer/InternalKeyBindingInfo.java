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
import java.util.List;

import javax.naming.OperationNotSupportedException;

/**
 * Value object for remote invocation from JVMs where the implementation class is not available.
 * 
 * @version $Id$
 */
public class InternalKeyBindingInfo implements InternalKeyBinding {

    private static final long serialVersionUID = 1L;

    final String implementationAlias;
    final int id;
    final String name;
    final InternalKeyBindingStatus status;
    final String certificateId;
    final int cryptoTokenId;
    final String keyPairAlias;
    final String nextKeyPairAlias;
    final List<InternalKeyBindingProperty<? extends Serializable>> properties;
    
    public InternalKeyBindingInfo(InternalKeyBinding internalKeyBinding) {
        this.implementationAlias = internalKeyBinding.getImplementationAlias();
        this.id = internalKeyBinding.getId();
        this.name = internalKeyBinding.getName();
        this.status = internalKeyBinding.getStatus();
        this.certificateId = internalKeyBinding.getCertificateId();
        this.cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        this.keyPairAlias = internalKeyBinding.getKeyPairAlias();
        this.nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        this.properties = internalKeyBinding.getCopyOfProperties();
    }
    
    @Override
    public void init(int id, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias,
            LinkedHashMap<Object, Object> dataMapToLoad) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public LinkedHashMap<Object, Object> getDataMapToPersist() {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public String getImplementationAlias() {
        return implementationAlias;
    }

    @Override
    public String getNextKeyPairAlias() {
        return nextKeyPairAlias;
    }

    @Override
    public void updateCertificateIdAndCurrentKeyAlias(String certificateId) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public void generateNextKeyPairAlias() {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public void assertCertificateCompatability(Certificate certificate) throws CertificateImportException {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public int getId() {
        return id;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public void setName(String name) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public InternalKeyBindingStatus getStatus() {
        return status;
    }

    @Override
    public void setStatus(InternalKeyBindingStatus status) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public String getCertificateId() {
        return certificateId;
    }

    @Override
    public void setCertificateId(String certificateId) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public int getCryptoTokenId() {
        return cryptoTokenId;
    }

    @Override
    public void setCryptoTokenId(int cryptoTokenId) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public String getKeyPairAlias() {
        return keyPairAlias;
    }

    @Override
    public void setKeyPairAlias(String keyPairAlias) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public InternalKeyBindingProperty<? extends Serializable> getProperty(String name) {
        for (InternalKeyBindingProperty<? extends Object> current : properties) {
            if (current.getName().equals(name)) {
                return current;
            }
        }
        return null;
    }

    @Override
    public void setProperty(String name, Serializable value) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public List<InternalKeyBindingProperty<? extends Serializable>> getCopyOfProperties() {
        return properties;
    }
}
