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
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;

/**
 * Each instance of this class represents a slot on a P11 module.
 * Use an instance of this class for all your access of a specific P11 slot.
 * Use {@link P11Slot#getProvider()} to get a provider for the slot.
 *
 * @version $Id$
 */
public class P11Slot {

    private static final Logger log = Logger.getLogger(P11Slot.class);

    /** Used for library key map when a sun configuration file is used to specify a token (slot). In this case only one lib could be used. */
    private static final String ONLY_ONE = "onlyOne";
    
    private final static Map<String,P11Slot> slotMap = new HashMap<String, P11Slot>();
    private final Map<Integer, P11SlotUser> p11SlotUserMap = new HashMap<Integer, P11SlotUser>();
    private final Pkcs11SlotLabelType slotLabelType;
    private final String slotLabel;
    private final String sharedLibrary;
    private final String sunP11ConfigFileName;
    private final Provider provider;
    private final String libraryFileName;
    
    private P11Slot(final Pkcs11SlotLabelType slotLabelType, final String slotLabel, final String sharedLibrary, final String attributesFile,
            final String friendlyName) throws NoSuchSlotException {
        this.slotLabelType = slotLabelType;
        this.slotLabel = slotLabel;
        this.sharedLibrary = sharedLibrary;
        this.sunP11ConfigFileName = null;
        this.libraryFileName = new File(sharedLibrary).getName();
        provider = Pkcs11SlotLabel.getP11Provider(slotLabel, slotLabelType, sharedLibrary, attributesFile);
        if (provider==null) {
            throw new NoSuchSlotException("Slot labeled " + slotLabel + " could not be located.");
        }
        addProvider();
    }

    private P11Slot(final String sunP11ConfigFileName) throws NoSuchSlotException {
        this.slotLabelType = Pkcs11SlotLabelType.SUN_FILE;
        this.sunP11ConfigFileName = sunP11ConfigFileName;
        this.slotLabel = null;
        this.sharedLibrary = null;
        this.libraryFileName = ONLY_ONE;
        this.provider = new Pkcs11SlotLabel(Pkcs11SlotLabelType.SUN_FILE, null).getProvider(sunP11ConfigFileName, null, null);
        if (this.provider==null) {
            throw new NoSuchSlotException("Slot configured in " + sunP11ConfigFileName + " could not be located.");
        }
        addProvider();
    }

    private void addProvider() {
        if (Security.getProvider(provider.getName())!=null) {
            Security.removeProvider(provider.getName());
        }
        Security.addProvider(provider);
        if (log.isDebugEnabled()) {
            log.debug("Provider successfully added: "+provider);
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
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated
     * @throws NoSuchSlotException if no slot with the label defined by slotLabel could be found
     */
    public static P11Slot getInstance(final String slotLabel, final String sharedLibrary, final Pkcs11SlotLabelType slotLabelType, 
            final String attributesFile, final P11SlotUser token, final int id) throws CryptoTokenOfflineException, NoSuchSlotException {       
        final String friendlyName = slotLabel + sharedLibrary + slotLabelType.toString();
        return getInstance(friendlyName, slotLabel, sharedLibrary, slotLabelType, attributesFile, token, id);
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
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated
     * @throws NoSuchSlotException if no slot by the given label could be found
     */
    public static P11Slot getInstance(final String friendlyName, final String slotLabel, final String sharedLibrary, final Pkcs11SlotLabelType slotLabelType, 
            final String attributesFile, final P11SlotUser p11SlotUser, final int id) throws NoSuchSlotException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
        	log.debug("P11Slot.getInstance(): "+String.valueOf(slotLabelType)+"'"+slotLabel+"', '"+sharedLibrary+"', "+", '"+attributesFile+"', "+id);
        }
        return getInstance(slotLabelType, friendlyName, slotLabel, sharedLibrary, attributesFile, null, p11SlotUser, id);
    }
    /**
     * As {@link #getInstance(String, String, boolean, String, org.ejbca.util.keystore.P11Slot.P11SlotUser)} but is using config file instead parameters. Do only use this method if the P11 shared library is ony specified in this config file.
     * @param sunP11ConfigFileName name of config file
     * @param p11SlotUser Token that should use this object.
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return a new P11Slot instance
     * @throws CryptoTokenOfflineException
     * @throws NoSuchSlotException if no slot defined by the label in configFileName could be found.
     */
    public static P11Slot getInstance(final String sunP11ConfigFileName, final P11SlotUser p11SlotUser, final int id) throws NoSuchSlotException, CryptoTokenOfflineException {
        if (log.isDebugEnabled()) {
            log.debug("P11Slot.getInstance(): '"+sunP11ConfigFileName+"', "+Pkcs11SlotLabelType.SUN_FILE.toString()+", "+id);
        }
        return getInstance(Pkcs11SlotLabelType.SUN_FILE, null, null, null, null, sunP11ConfigFileName, p11SlotUser, id);
    }

    private static P11Slot getInstance(final Pkcs11SlotLabelType slotLabelType, final String friendlyName, final String slotLabel, final String sharedLibrary,
            final String attributesFile, final String sunP11ConfigFileName, final P11SlotUser p11SlotUser, final int id) throws NoSuchSlotException, CryptoTokenOfflineException {
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
                        p11Slot = new P11Slot(sunP11ConfigFileName);
                    } else {
                        p11Slot = new P11Slot(slotLabelType, slotLabel, sharedLibrary, attributesFile, friendlyName);
                    }
                    slotMap.put(slotMapKey, p11Slot);
                }
                p11Slot.p11SlotUserMap.put(Integer.valueOf(id), p11SlotUser);
            }
            return p11Slot;
        } catch (NoSuchSlotException e) {
            throw e;
        } catch (Exception e) {
            throw new CryptoTokenOfflineException(InternalResources.getInstance().getLocalizedMessage("token.errorcreatetoken", id), e);
        }
    }
}
