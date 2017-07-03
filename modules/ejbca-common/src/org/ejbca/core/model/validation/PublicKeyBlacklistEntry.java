/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General                  *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.model.validation;

import java.io.Serializable;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;
import org.cesecore.keys.validation.KeyGeneratorSources;

/**
 * Domain class representing a public key blacklist entry.
 *  
 *
 * @version $Id$
 */
public class PublicKeyBlacklistEntry extends UpgradeableDataHashMap implements Serializable, Cloneable {

    private static final long serialVersionUID = -315759758359854900L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklistEntry.class);

    /** Public key fingerprint digest algorithm. */
    public static final String DIGEST_ALGORITHM = "SHA-256";


    //    /** List separator. */
    //    private static final String LIST_SEPARATOR = ";";

    protected static final InternalResources intres = InternalResources.getInstance();

    public static final float LATEST_VERSION = 1F;

    public static final String SOURCE = "source";
    public static final String KEYSPEC = "keySpec";
    public static final String FINGERPRINT = "fingerprint";
    public static final String PUBLIC_KEY = "publicKey";

    // Values used for lookup that are not stored in the data hash map.
    private int id;
    private int source;
    private String keyspec;
    private String fingerprint;

    /** Public key reference (set while validate). */
    protected PublicKey publicKey;
    
    /**
     * Creates a new instance.
     */
    public PublicKeyBlacklistEntry() {
        init();
    }

    /**
     * Initializes uninitialized data fields.
     */
    public void init() {
        if (null == data.get(VERSION)) {
            data.put(VERSION, new Float(LATEST_VERSION));
        }
    }

    /**
     * Gets the key public key blacklist id.
     * @return
     */
    public int getID() {
        return id;
    }

    /**
     * Sets the key public key blacklist id.
     * @param id
     */
    public void setID(int id) {
        this.id = id;
    }   

    /**
     * Gets the key spec, see for instance {@link AlgorithmConstants#KEYALGORITHM_RSA}.
     * @return the key spec string (i.e. 'RSA2048').
     */
    public String getKeyspec() {
        return keyspec;
    }

    /**
     * Sets the key spec.
     * @param keyspec the key spec string.
     */
    public void setKeyspec(String keyspec) {
        this.keyspec = keyspec;
    }
    
    /**
     * Gets the fingerprint.
     */
    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * Sets the fingerprint.
     * @param fingerprint
     */
    public void setFingerprint(String fingerprint) {
        this.fingerprint = fingerprint;
    }

    /**
     * Gets the source index, see {@link KeyGeneratorSources}
     * @return the source index.
     */
    public int getSource() {
        return source;
    }

    /**
     * Sets the source index, see {@link KeyGeneratorSources}
     
     * @param source the index
     */
    public void setSource(int source) {
        this.source = source;
    }

    /**
     * Gets the public key string.
     * @return the base64 encoded public key.
     */
    public String getPublicKeyString() {
        return (String) data.get(PUBLIC_KEY);
    }

    /**
     * Sets the the public key string.
     * @param publicKey the base64 encoded public key.
     */
    public void setPublicKeyString(String publicKey) {
        data.put(PUBLIC_KEY, publicKey);
    }

    /**
     * Gets the public key.
     * @return the public key.
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Sets the public key.
     * @param publicKey the public key.
     */
    public void setPublicKey(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public float getLatestVersion() {
        return LATEST_VERSION;
    }

    @Override
    public void upgrade() {
        if (log.isTraceEnabled()) {
            log.trace(">upgrade: " + getLatestVersion() + ", " + getVersion());
        }
        if (Float.compare(LATEST_VERSION, getVersion()) != 0) {
            // New version of the class, upgrade.
            log.info(intres.getLocalizedMessage("publickeyblacklist.upgrade", new Float(getVersion())));
            init();
        }
    }
}
