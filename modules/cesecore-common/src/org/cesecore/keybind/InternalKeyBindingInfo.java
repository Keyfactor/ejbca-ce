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

import java.io.IOException;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.OperatorCreationException;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Value object for remote invocation from JVMs where the implementation class is not available.
 * 
 * @version $Id$
 */
public class InternalKeyBindingInfo implements InternalKeyBinding {
    private static final long serialVersionUID = 1L;

    private final String implementationAlias;
    private final int id;
    private final String name;
    private final InternalKeyBindingStatus status;
    private final InternalKeyBindingOperationalStatus operationalStatus;
    private final String certificateId;
    private final int cryptoTokenId;
    private final String keyPairAlias;
    private final String nextKeyPairAlias;
    private final Map<String, DynamicUiProperty<? extends Serializable>> properties;
    private final List<InternalKeyBindingTrustEntry> trustedCertificateReferences;
    private final List<InternalKeyBindingTrustEntry> signOcspResponseOnBehalf;
    private final List<String> ocspExtensions;
    private final String signatureAlgorithm;
    private boolean useIssuerNotBeforeAsArchiveCutoff;
    private String retentionPeriod;
    
    public InternalKeyBindingInfo(final InternalKeyBinding internalKeyBinding) {
        this.implementationAlias = internalKeyBinding.getImplementationAlias();
        this.id = internalKeyBinding.getId();
        this.name = internalKeyBinding.getName();
        this.status = internalKeyBinding.getStatus();
        this.operationalStatus = internalKeyBinding.getOperationalStatus(); 
        this.certificateId = internalKeyBinding.getCertificateId();
        this.cryptoTokenId = internalKeyBinding.getCryptoTokenId();
        this.keyPairAlias = internalKeyBinding.getKeyPairAlias();
        this.nextKeyPairAlias = internalKeyBinding.getNextKeyPairAlias();
        this.properties = internalKeyBinding.getCopyOfProperties();
        this.trustedCertificateReferences = internalKeyBinding.getTrustedCertificateReferences();
        this.signOcspResponseOnBehalf = internalKeyBinding.getSignOcspResponseOnBehalf();
        this.ocspExtensions = internalKeyBinding.getOcspExtensions();
        this.signatureAlgorithm = internalKeyBinding.getSignatureAlgorithm();
        if (internalKeyBinding instanceof OcspKeyBinding) {
            final OcspKeyBinding ocspKeyBinding = (OcspKeyBinding) internalKeyBinding;
            this.useIssuerNotBeforeAsArchiveCutoff = ocspKeyBinding.getUseIssuerNotBeforeAsArchiveCutoff();
            this.retentionPeriod = ocspKeyBinding.getRetentionPeriod() == null ? "1y" : ocspKeyBinding.getRetentionPeriod().toString();
        }
    }
    
    @Override
    public void init(int id, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias,
            LinkedHashMap<Object, Object> dataMapToLoad) {
        throw new UnsupportedOperationException();
    }

    @Override
    public LinkedHashMap<Object, Object> getDataMapToPersist() {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }

    @Override
    public void updateCertificateIdAndCurrentKeyAlias(final String newCertificateId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void generateNextKeyPairAlias() {
        throw new UnsupportedOperationException();
    }

    @Override
    public void assertCertificateCompatability(Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }

    @Override
    public InternalKeyBindingStatus getStatus() {
        return status;
    }

    @Override
    public void setStatus(InternalKeyBindingStatus status) {
        throw new UnsupportedOperationException();
    }

    @Override
    public InternalKeyBindingOperationalStatus getOperationalStatus() {
        return operationalStatus;
    }

    @Override
    public void setOperationalStatus(InternalKeyBindingOperationalStatus opStatus) {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public String getCertificateId() {
        return certificateId;
    }

    @Override
    public void setCertificateId(String certificateId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getCryptoTokenId() {
        return cryptoTokenId;
    }

    @Override
    public void setCryptoTokenId(int cryptoTokenId) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getKeyPairAlias() {
        return keyPairAlias;
    }

    @Override
    public void setKeyPairAlias(String keyPairAlias) {
        throw new UnsupportedOperationException();
    }

    @Override
    public DynamicUiProperty<? extends Serializable> getProperty(String propertyName) {
        return properties.get(propertyName);
    }

    @Override
    public void setProperty(String name, Serializable value) {
        throw new UnsupportedOperationException();
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
        throw new UnsupportedOperationException();
    }
    
    @Override
    public List<InternalKeyBindingTrustEntry> getSignOcspResponseOnBehalf() {
        return signOcspResponseOnBehalf;
    }

    @Override
    public void setSignOcspResponseOnBehalf(List<InternalKeyBindingTrustEntry> signOcspResponseOnBehalf) {
        throw new UnsupportedOperationException();
    }

    @Override
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @Override
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        throw new UnsupportedOperationException();
    }

    @Override
    public List<String> getOcspExtensions() {
        return ocspExtensions;
    }

    @Override
    public void setOcspExtensions(List<String> ocspExtensions) {
        throw new UnsupportedOperationException();
    }

    @Override
    public byte[] generateCsrForNextKeyPair(String providerName, KeyPair keyPair, String signatureAlgorithm, X500Name subjectDn)
            throws IOException, OperatorCreationException {
        throw new UnsupportedOperationException();
    }

    public String getRetentionPeriod() {
        return retentionPeriod;
    }

    public boolean useIssuerNotBeforeAsArchiveCutoff() {
        return useIssuerNotBeforeAsArchiveCutoff;
    }
}
