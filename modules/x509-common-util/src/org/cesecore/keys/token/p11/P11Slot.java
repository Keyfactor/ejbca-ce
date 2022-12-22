/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.keys.token.p11;

import java.io.File;
import java.security.AuthProvider;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.login.LoginException;

import org.apache.log4j.Logger;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;

/**
 * Each instance of this class represents a slot on a P11 module.
 * Use an instance of this class for all your access of a specific P11 slot.
 * Use {@link P11Slot#getProvider()} to get a provider for the slot.
 *
 */
public class P11Slot {

    private static final Logger log = Logger.getLogger(P11Slot.class);

    /** Used for library key map when a sun configuration file is used to specify a token (slot). In this case only one lib could be used. */
    private static final String ONLY_ONE = "onlyOne";
    
    private final static Map<String,P11Slot> slotMap = new HashMap<>();
    private final Map<Integer, P11SlotUser> p11SlotUserMap = new HashMap<>();
    private final Pkcs11SlotLabelType slotLabelType;
    private final String slotLabel;
    private final String sharedLibrary;
    private final String sunP11ConfigFileName;
    private Provider provider;
    private final String libraryFileName;
    
    private P11Slot(final Pkcs11SlotLabelType slotLabelType, final String slotLabel, final String sharedLibrary, final String attributesFile,
            boolean addProvider) throws NoSuchSlotException {
        this.slotLabelType = slotLabelType;
        this.slotLabel = slotLabel;
        this.sharedLibrary = sharedLibrary;
        this.sunP11ConfigFileName = null;
        this.libraryFileName = new File(sharedLibrary).getName();
        provider = Pkcs11SlotLabel.getP11Provider(slotLabel, slotLabelType, sharedLibrary, attributesFile);
        if (provider==null) {
            throw new NoSuchSlotException("Slot labeled " + slotLabel + " could not be located.");
        }
        addProviderIfNotExisting(addProvider);
    }

    private P11Slot(final String sunP11ConfigFileName, boolean addProvider) throws NoSuchSlotException {
        this.slotLabelType = Pkcs11SlotLabelType.SUN_FILE;
        this.sunP11ConfigFileName = sunP11ConfigFileName;
        this.slotLabel = null;
        this.sharedLibrary = null;
        this.libraryFileName = ONLY_ONE;
        this.provider = new Pkcs11SlotLabel(Pkcs11SlotLabelType.SUN_FILE, null).getProvider(sunP11ConfigFileName, null, null);
        if (this.provider==null) {
            throw new NoSuchSlotException("Slot configured in " + sunP11ConfigFileName + " could not be located.");
        }
        addProviderIfNotExisting(addProvider);
    }

    /** Add a PKCS11 Crypto Provider to Java Security.addProvider, if it is not already added, and add==true.
     * The add parameter can seem redundant, but it is here in order to centralize control of what is added as a 
     * Crypto Provider, instead if distributing it to multiple places in the code.
     * @param add default value should be true, set to false to create a P11 slot without actually adding the P11 provider to Java Security
     */
    private void addProviderIfNotExisting(boolean add) {
        // If we already have a provider installed, it means there is another Crypto Token already using this slot
        // It can potentially be a Database Integrity Protection Crypto Token
        // We can't remove the already existing provider as that will cause the existing one to stop working. 
        // A classic error message when that happens is: 
        // java.security.InvalidKeyException: Private key must be instance of RSAPrivate(Crt)Key or have PKCS#8 encoding
        // Some HSMs (like Thales) only have one slot so in many cases it is a must to be able to use the same slot for
        // database integrity protection and a Crypto Token for CAs
        if (Security.getProvider(provider.getName()) != null) {
            // Because of the above, and how Sun P11 Provider works, we can re-use the existing provider
            // Of course, of this provider is not working (disconnected to HSM was disconnected or similar), this 
            // P11Slot will also just not work, while a remove and re-add might have caused it to start working
            provider = Security.getProvider(provider.getName());
            log.info("Found an existing PKCS#11 Provider while activating Crypto Token, re-using that instead of a new one: "+provider.getName());
        } else {
        	// Give the possibility to create a P11 slot without actually adding the P11 provider to Java Security
            if (add) {
                Security.addProvider(provider);
                if (log.isDebugEnabled()) {
                    log.debug("PKCS#11 Provider successfully added: "+provider.getName());
                }
            } else {
                log.info("Did not find an existing PKCS#11 Provider while activating Crypto Token, but was configured to not add one either: "+provider.getName());
            }
        }
    }

    @Override
    public String toString() {
        if (Pkcs11SlotLabelType.SUN_FILE.equals(slotLabelType)) {
            return "PKCS#11, Sun configuration file name: " + sunP11ConfigFileName;
        }
        return "PKCS#11 slot " + slotLabel + " using library " + sharedLibrary + ".";
    }

    /** Reset the HSM. Could be done if it has stopped working in a try to get it working again. */
    public void reset() {
        synchronized (slotMap) {
            for (final P11Slot slot : slotMap.values()) {
                if (slot.libraryFileName.equals(libraryFileName)) {
                    for (final P11SlotUser p11SlotUser : slot.p11SlotUserMap.values()) {
                        try {
                            p11SlotUser.deactivate();
                        } catch (Exception e) {
                            log.error("Not possible to deactivate token.", e);
                        }
                    }
                    if (Pkcs11SlotLabelType.SUN_FILE.equals(slotLabelType)) {
                        break;
                    }
                }
            }
        }
    }

    /** Unload if last active token on slot */
    public void logoutFromSlotIfNoTokensActive() {
        synchronized (slotMap) {
            for (final P11SlotUser p11SlotUser : p11SlotUserMap.values()) {
                if (p11SlotUser.isActive()) {
                    return;
                }
            }
        }
        if (provider instanceof AuthProvider) {
            try {
                ((AuthProvider)provider).logout();
                if (log.isDebugEnabled()) {
                    log.debug("PKCS#11 session terminated for \"" + toString() + "\".");
                }
            } catch (LoginException e) {
                log.warn("Not possible to logout from PKCS#11 Session. HW problems?", e);
            }
        } else {
            log.warn("Not possible to logout from PKCS#11 provider '" + toString() + "'. It is not implementing '" + AuthProvider.class.getCanonicalName() + "'.");
        }
    }

    /** @return the provider of the slot. */
    public Provider getProvider() {
        return provider;
    }

    /**
     * Get P11 slot instance. Only one instance (provider) will ever be created for each slot regardless of how many times this method is called.
     * @param slotLabel the labeling of the slot, regardless of label type. 
     * @param sharedLibrary file path of shared
     * @param slotLabelType The type of the label. May be a slot number [0...9]*, slot index i[0...9]* or a label.
     * @param attributesFile Attributes file. Optional. Set to null if not used
     * @param token Token that should use this object
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @param addProvider default value should be true, set to false to create a P11 slot without actually adding the P11 provider to Java Security
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated
     * @throws NoSuchSlotException if no slot with the label defined by slotLabel could be found
     */
    public static P11Slot getInstance(final String slotLabel, final String sharedLibrary, final Pkcs11SlotLabelType slotLabelType, 
            final String attributesFile, final P11SlotUser token, final int id, boolean addProvider) throws CryptoTokenOfflineException, NoSuchSlotException {       
        final String friendlyName = slotLabel + sharedLibrary + slotLabelType.toString();
        return getInstance(friendlyName, slotLabel, sharedLibrary, slotLabelType, attributesFile, token, id, addProvider);
    }

    /**
     * Get P11 slot instance. Only one instance (provider) will ever be created for each slot regardless of how many times this method is called.
     * @param friendlyName name to identify the instance
     * @param slotLabel the labeling of the slot, regardless of label type. 
     * @param sharedLibrary file path of shared
     * @param slotLabelType The type of the label. May be a slot number [0...9]*, slot index i[0...9]* or a label. 
     * @param attributesFile Attributes file. Optional. Set to null if not used
     * @param p11SlotUser Token that should use this object
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @param addProvider default value should be true, set to false to create a P11 slot without actually adding the P11 provider to Java Security
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated
     * @throws NoSuchSlotException if no slot by the given label could be found
     */
    public static P11Slot getInstance(final String friendlyName, final String slotLabel, final String sharedLibrary, final Pkcs11SlotLabelType slotLabelType, 
            final String attributesFile, final P11SlotUser p11SlotUser, final int id, boolean addProvider) throws NoSuchSlotException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("P11Slot.getInstance(): "+String.valueOf(slotLabelType)+"'"+slotLabel+"', '"+sharedLibrary+"', "+", '"+attributesFile+"', "+id);
        }
        return getInstance(slotLabelType, friendlyName, slotLabel, sharedLibrary, attributesFile, null, p11SlotUser, id, addProvider);
    }
    
    /**
     * As {@link #getInstance(String, String, boolean, String, org.ejbca.util.keystore.P11Slot.P11SlotUser)} but is using config file instead of parameters. 
     * Do only use this method if the P11 shared library is only specified in this config file.
     * @param sunP11ConfigFileName name of config file
     * @param p11SlotUser Token that should use this object.
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @param addProvider default value should be true, set to false to create a P11 slot without actually adding the P11 provider to Java Security
     * @return a new P11Slot instance
     * @throws CryptoTokenOfflineException
     * @throws NoSuchSlotException if no slot defined by the label in configFileName could be found.
     */
    public static P11Slot getInstance(final String sunP11ConfigFileName, final P11SlotUser p11SlotUser, final int id, boolean addProvider) throws NoSuchSlotException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("P11Slot.getInstance(): '"+sunP11ConfigFileName+"', "+Pkcs11SlotLabelType.SUN_FILE.toString()+", "+id);
        }
        return getInstance(Pkcs11SlotLabelType.SUN_FILE, null, null, null, null, sunP11ConfigFileName, p11SlotUser, id, addProvider);
    }

    private static P11Slot getInstance(final Pkcs11SlotLabelType slotLabelType, final String friendlyName, final String slotLabel, final String sharedLibrary,
            final String attributesFile, final String sunP11ConfigFileName, final P11SlotUser p11SlotUser, final int id, boolean addProvider) throws NoSuchSlotException, CryptoTokenOfflineException {
        try {
            final String slotMapKey;
            if (Pkcs11SlotLabelType.SUN_FILE.equals(slotLabelType)) {
                if (sunP11ConfigFileName==null) {
                    throw new IllegalStateException("Can't initialize PKCS#11 slot of type "+slotLabelType.name()+" without providing a config file.");
                }
                slotMapKey = new File(sunP11ConfigFileName).getName();
            } else {
                if (slotLabel==null || sharedLibrary==null) {
                    throw new IllegalStateException("Can't initialize PKCS#11 slot of type "+slotLabelType.name()+" without providing library and slot label.");
                }
                slotMapKey = friendlyName;
            }
            P11Slot p11Slot;
            synchronized (slotMap) {
                p11Slot = slotMap.get(slotMapKey);
                if (p11Slot==null) {
                    if (Pkcs11SlotLabelType.SUN_FILE.equals(slotLabelType)) {
                        p11Slot = new P11Slot(sunP11ConfigFileName, addProvider);
                    } else {
                        p11Slot = new P11Slot(slotLabelType, slotLabel, sharedLibrary, attributesFile, addProvider);
                    }
                    slotMap.put(slotMapKey, p11Slot);
                }
                p11Slot.p11SlotUserMap.put(id, p11SlotUser);
            }
            return p11Slot;
        } catch (NoSuchSlotException e) {
            throw e;
        } catch (Exception e) {
            final String msg = "Error when creating Crypto Token with ID " + id +  ".";
            throw new CryptoTokenOfflineException(msg, e);
        }
    }
}
