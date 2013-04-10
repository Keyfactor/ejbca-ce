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

import java.util.LinkedHashMap;

import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * Holder of general signer mapping relevant properties.
 * 
 * @version $Id$
 */
public abstract class SignerMappingBase extends UpgradeableDataHashMap implements SignerMapping {

    private static final long serialVersionUID = 1L;
    
    private int signerMappingId;
    private String name;
    private SignerMappingStatus status;
    private String certificateId;
    private int cryptoTokenId;
    private String keyPairAlias;
    
    protected SignerMappingBase() {
        super();
    }

    @Override
    public void init(int signerMappingId, String name, SignerMappingStatus status, String certificateId, int cryptoTokenId, String keyPairAlias, LinkedHashMap<Object, Object> dataMap) {
        this.signerMappingId = signerMappingId;
        setName(name);
        setStatus(status);
        setCertificateId(certificateId);
        setCryptoTokenId(cryptoTokenId);
        setKeyPairAlias(keyPairAlias);
        loadData(dataMap);
    }

    @Override
    public int getId() { return signerMappingId; }
    @Override
    public String getName() { return name; }
    @Override
    public void setName(final String name) { this.name = name; }
    @Override
    public SignerMappingStatus getStatus() { return status; }
    @Override
    public void setStatus(final SignerMappingStatus status) { this.status = status; }
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
    public LinkedHashMap<Object, Object> getDataMapToPersist() {
        return (LinkedHashMap<Object, Object>) saveData();
    }
    
    @Override
    public abstract float getLatestVersion();

    @Override
    public void upgrade() {
        // TODO: Here we can to upgrades of base properties when needed.. we do not to store a version for this as well tough..
        upgrade(getLatestVersion(), getVersion());
    }

    /** Invoked after the all data has been loaded in init(...) */
    protected abstract void upgrade(final float latestVersion, final float currentVersion);

    /** Store data in the undelying map. Encourages use of String valued keys. */
    protected void putData(final String key, final Object value) { data.put(key, value); }

    /** @return data from the undelying map. Encourages use of String valued keys. */
    protected <T> T getData(final String key, final T defaultValue) {
        final T ret = (T) data.get(key);
        return ret==null ? defaultValue : ret;
    }
}
