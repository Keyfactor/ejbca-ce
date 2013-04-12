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

import java.security.cert.Certificate;
import java.util.LinkedHashMap;

import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * Holder of general InternalKeyBinding relevant properties.
 * 
 * @version $Id$
 */
public abstract class InternalKeyBindingBase extends UpgradeableDataHashMap implements InternalKeyBinding {

    private static final long serialVersionUID = 1L;
    private static final String PROP_NEXT_KEY_PAIR_ALIAS = "nextKeyPairAlias";
    private static final String PROP_NEXT_KEY_PAIR_COUNTER = "nextKeyPairCounter";
    private static final String BASECLASS_PREFIX = "BASECLASS_";
    public static final String SUBCLASS_PREFIX = "SUBCLASS_";
    
    private int internalKeyBindingId;
    private String name;
    private InternalKeyBindingStatus status;
    private String certificateId;
    private int cryptoTokenId;
    private String keyPairAlias;
    
    protected InternalKeyBindingBase() {
        super();
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
    public InternalKeyBindingStatus getStatus() { return status; }
    @Override
    public void setStatus(final InternalKeyBindingStatus status) { this.status = status; }
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
    private void setNextKeyPairAlias(final String nextKeyPairAlias) {
        putData(PROP_NEXT_KEY_PAIR_ALIAS, nextKeyPairAlias);
    }
    private Long getNextKeyPairCounter() {
        return getDataInternal(PROP_NEXT_KEY_PAIR_COUNTER, Long.valueOf(0L));
    }
    private void setNextKeyPairCounter(Long nextKeyPairCounter) {
        putDataInternal(PROP_NEXT_KEY_PAIR_COUNTER, nextKeyPairCounter);
    }

    @Override
    public void updateCertificateIdAndCurrentKeyAlias(String certificateId) {
        setCertificateId(certificateId);
        setKeyPairAlias(getNextKeyPairAlias());
        setNextKeyPairAlias(null);
    }

    @Override
    public void generateNextKeyPairAlias() {
        if (getNextKeyPairAlias() != null) {
            return;
        }
        final String currentKeyPairAlias = getKeyPairAlias();
        String nextKeyPairAlias;
        Long nextKeyPairCounter = getNextKeyPairCounter();
        int indexOfPostFix = currentKeyPairAlias.lastIndexOf("_" + nextKeyPairCounter);
        nextKeyPairCounter = Long.valueOf(nextKeyPairCounter.longValue() + 1L);
        if (indexOfPostFix == -1) {
            // No postfix present, append
            nextKeyPairAlias = currentKeyPairAlias + "_" + nextKeyPairCounter.toString();
        } else {
            // Post fix present, replace
            nextKeyPairAlias = currentKeyPairAlias.substring(0, indexOfPostFix) + "_" + nextKeyPairCounter.toString();
        }
        setNextKeyPairAlias(nextKeyPairAlias);
        setNextKeyPairCounter(nextKeyPairCounter);
    }
    
    @Override
    @SuppressWarnings("unchecked")
    public LinkedHashMap<Object, Object> getDataMapToPersist() {
        return (LinkedHashMap<Object, Object>) saveData();
    }
    
    @Override
    public abstract float getLatestVersion();
    @Override
    public abstract void assertCertificateCompatability(Certificate certificate) throws CertificateImportException;

    @Override
    public void upgrade() {
        // TODO: Here we can to upgrades of base properties when needed.. we do not to store a version for this as well tough..
        upgrade(getLatestVersion(), getVersion());
    }

    /** Invoked after the all data has been loaded in init(...) */
    protected abstract void upgrade(final float latestVersion, final float currentVersion);

    /** Store data in the undelying map. Encourages use of String valued keys. */
    protected void putData(final String key, final Object value) {
        data.put(SUBCLASS_PREFIX + key, value);
    }

    /** @return data from the undelying map. Encourages use of String valued keys. */
    @SuppressWarnings("unchecked")
    protected <T> T getData(final String key, final T defaultValue) {
        final T ret = (T) data.get(SUBCLASS_PREFIX + key);
        return ret==null ? defaultValue : ret;
    }

    /** Store data in the undelying map. Encourages use of String valued keys. */
    private void putDataInternal(final String key, final Object value) {
        data.put(BASECLASS_PREFIX + key, value);
    }

    /** @return data from the undelying map. Encourages use of String valued keys. */
    @SuppressWarnings("unchecked")
    private <T> T getDataInternal(final String key, final T defaultValue) {
        final T ret = (T) data.get(BASECLASS_PREFIX + key);
        return ret==null ? defaultValue : ret;
    }
}
