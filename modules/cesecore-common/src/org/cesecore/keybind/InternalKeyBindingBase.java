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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.log4j.Logger;
import org.cesecore.config.AvailableExtendedKeyUsagesConfiguration;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.util.ui.DynamicUiProperty;

/**
 * Holder of general InternalKeyBinding relevant properties.
 * 
 * @version $Id$
 */
public abstract class InternalKeyBindingBase extends UpgradeableDataHashMap implements InternalKeyBinding {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(InternalKeyBindingBase.class);
    private static final String PROP_NEXT_KEY_PAIR_ALIAS = "nextKeyPairAlias";
    private static final String PROP_TRUSTED_CERTIFICATE_REFERENCES = "trustedCertificateReferences";
    private static final String PROP_SIGNATURE_ALGORITHM = "signatureAlgorithm";
    private static final String PROP_OCSP_EXTENSION = "ocspExtensions";
    private static final String BASECLASS_PREFIX = "BASECLASS_";
    public static final String SUBCLASS_PREFIX = "SUBCLASS_";
    
    private int internalKeyBindingId;
    private String name;
    private InternalKeyBindingStatus status;
    private InternalKeyBindingOperationalStatus operationalStatus;
    private String certificateId;
    private int cryptoTokenId;
    private String keyPairAlias;
    private List<InternalKeyBindingTrustEntry> trustedCertificateReferences;
    private List<String> ocspExtensions;
    private String signatureAlgorithm;
    
    private final LinkedHashMap<String,DynamicUiProperty<? extends Serializable>> propertyTemplates = new LinkedHashMap<>();
    
    protected void addProperty(DynamicUiProperty<? extends Serializable> property) {
        propertyTemplates.put(property.getName(), property);
    }
    
    @Override
    public Map<String, DynamicUiProperty<? extends Serializable>> getCopyOfProperties() {
        final LinkedHashMap<String, DynamicUiProperty<? extends Serializable>> ret = new LinkedHashMap<>();
        for (String key : propertyTemplates.keySet()) {
            DynamicUiProperty<? extends Serializable> current = propertyTemplates.get(key);
            final DynamicUiProperty<? extends Serializable> clone = current.clone();
            clone.setValueGeneric(getProperty(clone.getName()).getValue());
            ret.put(key, clone);
        }
        return ret;
    }

    @Override
    public DynamicUiProperty<? extends Serializable> getProperty(final String name) {
        DynamicUiProperty<? extends Serializable> property = propertyTemplates.get(name);
        property = property.clone();
        property.setValueGeneric(getData(name, property.getDefaultValue()));
        return property;
    }

    @Override
    public void setProperty(final String name, Serializable value) {
        putData(name, value);
    }

    @Override
    public void init(int internalKeyBindingId, String name, InternalKeyBindingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, LinkedHashMap<Object, Object> dataMap) {
        this.internalKeyBindingId = internalKeyBindingId;
        setName(name);
        setStatus(status);
        setCertificateId(certificateId);
        setCryptoTokenId(cryptoTokenId);
        setKeyPairAlias(keyPairAlias);
        if (dataMap.get(VERSION) == null) {
            // If we are creating a new object we need a version
            dataMap.put(VERSION, new Float(getLatestVersion()));
        }
        loadData(dataMap);
    }

    @Override
    public int getId() { return internalKeyBindingId; }
    @Override
    public String getName() { return name; }
    @Override
    public void setName(final String name) { this.name = name; }
    @Override
    public InternalKeyBindingStatus getStatus() {
        if (status==null) {
            status = InternalKeyBindingStatus.DISABLED;
        }
        return status;
    }
    @Override
    public void setStatus(final InternalKeyBindingStatus status) {
        if (status==null) {
            this.status = InternalKeyBindingStatus.DISABLED;
        } else {
            this.status = status;
        }
    }
    
    @Override
    public InternalKeyBindingOperationalStatus getOperationalStatus() {
        if (operationalStatus == null) {
            operationalStatus = InternalKeyBindingOperationalStatus.OFFLINE;
        }
        return operationalStatus;
    }
    @Override
    public void setOperationalStatus(final InternalKeyBindingOperationalStatus operationalStatus) {
        if (operationalStatus == null) {
            this.operationalStatus = InternalKeyBindingOperationalStatus.OFFLINE;
        } else {
            this.operationalStatus = operationalStatus;
        }
    }
    
    @Override
    public String getCertificateId() { return certificateId; }
    @Override
    public void setCertificateId(final String certificateId) { this.certificateId = certificateId; }
    @Override
    public int getCryptoTokenId() { return cryptoTokenId; }
    @Override
    public void setCryptoTokenId(final int cryptoTokenId) { this.cryptoTokenId = cryptoTokenId; }
    @Override
    public String getKeyPairAlias() { return keyPairAlias; }
    @Override
    public void setKeyPairAlias(final String keyPairAlias) { this.keyPairAlias = keyPairAlias; }

    @Override
    public String getNextKeyPairAlias() {
        return getData(PROP_NEXT_KEY_PAIR_ALIAS, (String)null);
    }
    @Override
    public void setNextKeyPairAlias(final String nextKeyPairAlias) {
        putData(PROP_NEXT_KEY_PAIR_ALIAS, nextKeyPairAlias);
    }

    @Override
    public void updateCertificateIdAndCurrentKeyAlias(String certificateId) {
        setCertificateId(certificateId);
        setKeyPairAlias(getNextKeyPairAlias());
        setNextKeyPairAlias(null);
    }

    private static final SimpleDateFormat DATE_FORMAT_MS = new SimpleDateFormat("yyyyMMddHHmmssSSS");
    private static final Pattern DATE_FORMAT_PATTERN = Pattern.compile("_\\d{8}\\d{6}$");
    private static final Pattern DATE_FORMAT_PATTERN_MS = Pattern.compile("_\\d{8}\\d{9}$");
    
    /** Replace existing postfix or generate add a new one (using current time with millisecond granularity). */
    private String getNewAlias(final String oldAlias) {
        final Matcher matcherMs = DATE_FORMAT_PATTERN_MS.matcher(oldAlias);
        final String newPostFix = "_" + DATE_FORMAT_MS.format(new Date());
        // Check if the key alias postfix is in EJBCA 6.2.4+ format
        if (matcherMs.find()) {
            // Replace postfix in millisecond format
            return matcherMs.replaceAll(newPostFix);
        } else {
            final Matcher matcher = DATE_FORMAT_PATTERN.matcher(oldAlias);
            // Check if the key alias postfix is in EJBCA 6.2.3- format
            if (matcher.find()) {
                // Replace postfix with millisecond format
                return matcher.replaceAll(newPostFix);
            } else {
                // No postfix, add one
                return oldAlias + newPostFix;
            }
        }
    }

    @Override
    public void generateNextKeyPairAlias() {
        final String currentKeyPairAlias = getKeyPairAlias();
        final String nextKeyPairAlias = getNewAlias(currentKeyPairAlias);
        if (log.isDebugEnabled()) {
            log.debug("nextKeyPairAlias for internalKeyBinding " + internalKeyBindingId + " will be " + nextKeyPairAlias);
        }
        setNextKeyPairAlias(nextKeyPairAlias);
    }

    @Override
    public List<InternalKeyBindingTrustEntry> getTrustedCertificateReferences() {
        if (trustedCertificateReferences == null) {
            trustedCertificateReferences = getDataInternal(PROP_TRUSTED_CERTIFICATE_REFERENCES, new ArrayList<InternalKeyBindingTrustEntry>());
        }
        // Return a shallow copy of the list
        final ArrayList<InternalKeyBindingTrustEntry> trustedCertificateReferences = new ArrayList<InternalKeyBindingTrustEntry>();
        trustedCertificateReferences.addAll(this.trustedCertificateReferences);
        return trustedCertificateReferences;
    }

    @Override
    public void setTrustedCertificateReferences(final List<InternalKeyBindingTrustEntry> trustedCertificateReferences) {
        this.trustedCertificateReferences = trustedCertificateReferences;
        // Always save it as an ArrayList that we know is Serializable
        final ArrayList<InternalKeyBindingTrustEntry> arrayList = new ArrayList<InternalKeyBindingTrustEntry>(trustedCertificateReferences.size());
        arrayList.addAll(trustedCertificateReferences);
        putDataInternal(PROP_TRUSTED_CERTIFICATE_REFERENCES, arrayList);
    }

    @Override
    public List<String> getOcspExtensions() {
        if (ocspExtensions == null) {
            ocspExtensions = getDataInternal(PROP_OCSP_EXTENSION, new ArrayList<String>());
        }
        final ArrayList<String> ocspExensions = new ArrayList<>();
        ocspExensions.addAll(this.ocspExtensions);
        return ocspExtensions;
    }
    
    @Override
    public void setOcspExtensions(List<String> ocspExtensions) {
        this.ocspExtensions = ocspExtensions;
        final ArrayList<String> arrayList = new ArrayList<>();
        arrayList.addAll(ocspExtensions);
        putDataInternal(PROP_OCSP_EXTENSION, arrayList);
    }
    
    @Override
    public String getSignatureAlgorithm() {
        if (signatureAlgorithm == null) {
            signatureAlgorithm = getDataInternal(PROP_SIGNATURE_ALGORITHM, null);
        }
        return signatureAlgorithm;
    }

    @Override
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        putDataInternal(PROP_SIGNATURE_ALGORITHM, signatureAlgorithm);
    }
    
    @Override
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMapToPersist() {
        return (LinkedHashMap<Object, Object>) saveData();
    }
    
    @Override
    public abstract float getLatestVersion();
    @Override
    public abstract void assertCertificateCompatability(Certificate certificate, final AvailableExtendedKeyUsagesConfiguration ekuConfig) throws CertificateImportException;

    @Override
    public void upgrade() {
        // TODO: Here we can to upgrades of base properties when needed.. we do not to store a version for this as well tough..
        upgrade(getLatestVersion(), getVersion());
    }

    /** Invoked after the all data has been loaded in init(...) */
    protected abstract void upgrade(final float latestVersion, final float currentVersion);

    /** Store data in the underlying map. Encourages use of String valued keys. */
    private void putData(final String key, final Object value) {
        data.put(SUBCLASS_PREFIX + key, value);
    }

    /** @return data from the underlying map. Encourages use of String valued keys. */
    @SuppressWarnings("unchecked")
    private <T> T getData(final String key, final T defaultValue) {
        final T ret = (T) data.get(SUBCLASS_PREFIX + key);
        return ret==null ? defaultValue : ret;
    }

    /** Store data in the underlying map. Encourages use of String valued keys. */
    private void putDataInternal(final String key, final Object value) {
        data.put(BASECLASS_PREFIX + key, value);
    }

    /** @return data from the underlying map. Encourages use of String valued keys. */
    @SuppressWarnings("unchecked")
    private <T> T getDataInternal(final String key, final T defaultValue) {
        final T ret = (T) data.get(BASECLASS_PREFIX + key);
        return ret==null ? defaultValue : ret;
    }
}
