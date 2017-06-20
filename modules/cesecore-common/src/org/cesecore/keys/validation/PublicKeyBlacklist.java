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

package org.cesecore.keys.validation;

import java.io.Serializable;
import java.security.PublicKey;

import org.apache.log4j.Logger;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.internal.InternalResources;
import org.cesecore.internal.UpgradeableDataHashMap;

/**
 * Domain class representing a public key blacklist entry.
 *  
 *
 * @version $Id: PublicKeyBlacklist.java 22117 2017-04-01 12:12:00Z anjakobs $
 */
public class PublicKeyBlacklist extends UpgradeableDataHashMap implements Serializable, Cloneable {

    private static final long serialVersionUID = -315759758359854900L;

    /** Class logger. */
    private static final Logger log = Logger.getLogger(PublicKeyBlacklist.class);

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
    public PublicKeyBlacklist() {
        init();
    }

    @Override
    protected Object clone() throws CloneNotSupportedException {
        // TODO Auto-generated method stub
        return super.clone();
    }


    /**
     * Initializes uninitialized data fields.
     */
    public void init() {
        if (null == data.get(VERSION)) {
            data.put(VERSION, new Float(LATEST_VERSION));
        }
//        if (null == data.get(SOURCE)) {
//            setSource(KeyGeneratorSources.UNKNOWN.getSource());
//        }
    }

    /**
     * Gets the key public key blacklist id.
     * @return
     */
    public int getPublicKeyBlacklistId() {
        return id;
    }

    /**
     * Sets the key public key blacklist id.
     * @param id
     */
    public void setPublicKeyBlacklistId(int id) {
        this.id = id;
    }
   
//    /**
//     * Gets the key generator source index, see {@link KeyGeneratorSources}.
//     */
//    public Integer getSource() {
//        return (Integer) data.get(SOURCE);
//    }
//
//    /**
//     * Sets the key generator source index, see {@link KeyGeneratorSources}.
//     * @param source the source index.
//     */
//    public void setSource(Integer source) {
//        data.put(SOURCE, source);
//    }

//    /**
//     * Gets the key specification.
//     * @return key specification string.
//     */
//    public String getKeySpec() {
//        return (String) data.get(KEYSPEC);
//    }
//
//    /**
//     * Sets the key specification.
//     * @param keySpec the key specification string.
//     */
//    public void setClasspath(String keySpec) {
//        data.put(KEYSPEC, keySpec);
//    }

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
