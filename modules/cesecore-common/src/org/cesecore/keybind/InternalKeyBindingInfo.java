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
package org.cesecore.keybind;

import java.io.Serializable;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.naming.OperationNotSupportedException;

import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Value object for remote invocation from JVMs where the implementation class is not available.
 * 
 * @version $Id$
 */
public class InternalKeyBindingInfo implements InternalKeyBinding {

    private static final long serialVersionUID = 1L;

    final private String implementationAlias;
    final private int id;
    final private String name;
    final private InternalKeyBindingStatus status;
    final private String certificateId;
    final private int cryptoTokenId;
    final private String keyPairAlias;
    final private String nextKeyPairAlias;
    final private Map<String, DynamicUiProperty<? extends Serializable>> properties;
    final private List<InternalKeyBindingTrustEntry> trustedCertificateReferences;
    final private String signatureAlgorithm;
    
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
        this.trustedCertificateReferences = internalKeyBinding.getTrustedCertificateReferences();
        this.signatureAlgorithm = internalKeyBinding.getSignatureAlgorithm();
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
    public void setNextKeyPairAlias(String nextKeyPairAlias) {
        throw new RuntimeException(new OperationNotSupportedException());
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
    public void assertCertificateCompatability(Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException {
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
    public DynamicUiProperty<? extends Serializable> getProperty(String name) {
        return properties.get(name);
    }

    @Override
    public void setProperty(String name, Serializable value) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public Map<String, DynamicUiProperty<? extends Serializable>> getCopyOfProperties() {
        return properties;
    }

    @Override
    public List<InternalKeyBindingTrustEntry> getTrustedCertificateReferences() {
        return trustedCertificateReferences;
    }

    @Override
    public void setTrustedCertificateReferences(List<InternalKeyBindingTrustEntry> trustedCertificateReferences) {
        throw new RuntimeException(new OperationNotSupportedException());
    }

    @Override
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        throw new RuntimeException(new OperationNotSupportedException());
    }
}
