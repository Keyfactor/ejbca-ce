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
import java.io.FileInputStream;
import java.io.IOException;
import java.security.AuthProvider;
import java.security.Provider;
import java.security.Security;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.security.auth.login.LoginException;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.util.KeyTools;

/**
 * Each instance of this class represents a slot on a P11 module.
 * Use an instance of this class for all your access of a specific P11 slot.
 * Use {@link P11Slot#getProvider()} to get a provider for the slot.
 *
 * Based on EJBCA version: P11Slot.java 11228 2011-01-19 11:34:11Z anatom
 * 
 * @version $Id$
 */
public class P11Slot {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(P11Slot.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    private final static Map<String,P11Slot> slotMap = new HashMap<String, P11Slot>();
    private final static Set<String> slotsBeingCreated = new HashSet<String>();
    private final static Map<String,Set<P11Slot>> libMap = new HashMap<String, Set<P11Slot>>();
    private final static Map<Integer, P11SlotUser> tokenMap = new HashMap<Integer, P11SlotUser>();
    final private String slotNr;
    final private String sharedLibrary;
    final private String attributesFile;
    final private boolean isIndex;
    final private Set<Integer> tokenids = new HashSet<Integer>();
    final private String sunP11ConfigFileName;
    final private Provider provider;
    private boolean isSettingProvider = false;
    private P11Slot(String _slotNr, String _sharedLibrary, boolean _isIndex, String _attributesFile) throws CryptoTokenOfflineException {
        this.slotNr = _slotNr;
        this.sharedLibrary = _sharedLibrary;
        this.isIndex = _isIndex;
        this.attributesFile = _attributesFile;
        this.sunP11ConfigFileName = null;
        this.provider = createProvider();
    }
    private P11Slot( String configFileName ) throws CryptoTokenOfflineException {
        this.sunP11ConfigFileName = configFileName;
        this.slotNr = null;
        this.sharedLibrary = null;
        this.isIndex = false;
        this.attributesFile = null;
        this.provider = createProvider();
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        if ( this.slotNr==null && this.sharedLibrary==null ) {
            return "P11, Sun configuration file name: "+this.sunP11ConfigFileName;
        }
        return "P11 slot "+(this.isIndex ? "index ":"#")+this.slotNr+" using library "+this.sharedLibrary+'.';
    }
    /**
     * Used for library key map when a sun configuration file is used to specify a token (slot). In this case only one lib could be used.
     */
    static private String ONLY_ONE = "onlyOne";
    /**
     * Reset the HSM. Could be done if it has stopped working in a try to get it working again.
     */
    public void reset() {
        final String mapName = this.sharedLibrary!=null ? new File(this.sharedLibrary).getName() : ONLY_ONE;
        for( P11Slot slot : libMap.get(mapName)) {
            for(Integer tokenId : slot.tokenids ) {
                try {
                    tokenMap.get(tokenId).deactivate();
                } catch (Exception e) {
                    log.error("Not possible to deactivate token.", e);
                }
            }
        }
    }
    /**
     * Get P11 slot instance. Only one instance (provider) will ever be created for each slot regardless of how many times this method is called.
     * @param slotNr number of the slot
     * @param sharedLibrary file path of shared
     * @param isIndex true if not slot number but index in slot list
     * @param attributesFile Attributes file. Optional. Set to null if not used
     * @param token Token that should use this object
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated, IllegalArgumentException if sharedLibrary is null.
     */
    public static P11Slot getInstance(String slotNr, String sharedLibrary, boolean isIndex, 
                                      String attributesFile, P11SlotUser token, int id) throws CryptoTokenOfflineException {
        
        return getInstance(null, slotNr, sharedLibrary, isIndex, attributesFile, token, id);
    }
    
    
    
    /**
     * Get P11 slot instance. Only one instance (provider) will ever be created for each slot regardless of how many times this method is called.
     * @param friendlyName name to identify the instance
     * @param slotNr number of the slot
     * @param sharedLibrary file path of shared
     * @param isIndex true if not slot number but index in slot list
     * @param attributesFile Attributes file. Optional. Set to null if not used
     * @param token Token that should use this object
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated, IllegalArgumentException if sharedLibrary is null.
     */
    public static P11Slot getInstance(String friendlyName, String slotNr, String sharedLibrary, boolean isIndex, 
                                      String attributesFile, P11SlotUser token, int id) throws CryptoTokenOfflineException {
        if (sharedLibrary == null) {
            throw new IllegalArgumentException("sharedLibrary = null");
        }
        if (log.isDebugEnabled()) {
        	log.debug("P11Slot.getInstance(): '"+slotNr+"', '"+sharedLibrary+"', "+isIndex+", '"+attributesFile+"', "+id);
        }
        return getInstance(new SlotDataParam(friendlyName, slotNr, sharedLibrary, isIndex, attributesFile), token, id);
    }
    /**
     * As {@link #getInstance(String, String, boolean, String, org.ejbca.util.keystore.P11Slot.P11SlotUser)} but is using config file instead parameters. Do only use this method if the P11 shared library is ony specified in this config file.
     * @param configFileName name of config file
     * @param token Token that should use this object.
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return a new P11Slot instance
     * @throws CATokenOfflineException
     */
    static public P11Slot getInstance(String configFileName, P11SlotUser token, int id) throws CryptoTokenOfflineException {
        return getInstance(new SlotDataConfigFile(configFileName), token, id);
    }
    static private P11Slot getInstance(ISlotData data, P11SlotUser token, int id) throws CryptoTokenOfflineException {
        tokenMap.put(Integer.valueOf(id), token);
        P11Slot slot = slotMap.get(data.getSlotLabel());
        if (slot==null) {
            synchronized( slotsBeingCreated ) {
                // test if another thread is currently creating the slot
                if ( slotsBeingCreated.contains(data.getSlotLabel()) ) {
                    while ( true ) {
                        slot = slotMap.get(data.getSlotLabel());
                        if ( slot!=null ) {
                            break; // don't wait if we got a slot now
                        } else if ( !slotsBeingCreated.contains(data.getSlotLabel()) ) {
                        	// thread creating slot failed
                            throw new CryptoTokenOfflineException(intres.getLocalizedMessage("token.errorcreatetoken", id)); 
                        }
                        // wait until another thread has created the slot
                        try {
                            slotsBeingCreated.wait();
                        } catch (InterruptedException e) {
                            throw new Error( "This should never happen.", e);
                        }
                        // the slot should now have been created by another thread
                    }
                } else {
                    try {
                        slotsBeingCreated.add(data.getSlotLabel());// show that this thread is creating the slot
                        slot = data.getNewP11Slot();
                        slotMap.put(data.getSlotLabel(), slot);
                        // Make this check here and not in the finally clause, making the check in the finally clause will only hide any
                        // CryptoTokenOfflineException thrown above, and strip the vital error information.
                        if ( slot==null ) {
                            throw new CryptoTokenOfflineException(intres.getLocalizedMessage("token.errorcreatetoken", id));
                        }
                    	// The above may throw a CryptoTokenOfflineException
                    } finally {
                        if ( slot==null ) {
                            slotsBeingCreated.remove(data.getSlotLabel());// show that creating the slot failed
                        }
                        slotsBeingCreated.notifyAll();// notify that the slot is now created
                    }
                    Set<P11Slot> libSet = libMap.get(data.getLibName());
                    if (libSet==null) {
                        libSet=new HashSet<P11Slot>();
                        libMap.put(data.getLibName(), libSet);
                    }
                    libSet.add(slot);
                }
            }
        }
        final Iterator<P11Slot> i = slotMap.values().iterator();
        while ( i.hasNext() ) {
            i.next().tokenids.remove(Integer.valueOf(id));
        }
        slot.tokenids.add(Integer.valueOf(id));
        return slot;
    }
    private static interface ISlotData {
        P11Slot getNewP11Slot() throws CryptoTokenOfflineException;
        String getSlotLabel();
        String getLibName();
    }
    private static class SlotDataConfigFile implements ISlotData {
        private final String configFileName;
        SlotDataConfigFile(String _configFileName) {
            this.configFileName = _configFileName;
        }
        public String getLibName() {
            return ONLY_ONE;
        }
        public P11Slot getNewP11Slot() throws CryptoTokenOfflineException {
            return new P11Slot(this.configFileName);
        }
        public String getSlotLabel() {
            return new File(this.configFileName).getName();
        }
    }
    private static class SlotDataParam implements ISlotData {
    	private final String friendlyName;
        private final String slotNr;
        private final String sharedLibrary;
        private final String libName;
        private final boolean isIndex; 
        private final String attributesFile;
        SlotDataParam(String _friendlyName, String _slotNr, String _sharedLibrary, boolean _isIndex, 
                      String _attributesFile) {
            this.slotNr = _slotNr;
            this.sharedLibrary = _sharedLibrary;
            this.isIndex = _isIndex;
            this.attributesFile = _attributesFile;
            this.libName = new File(this.sharedLibrary).getName();
            this.friendlyName = _friendlyName;
        }
        public P11Slot getNewP11Slot() throws CryptoTokenOfflineException {
            return new P11Slot(this.slotNr, this.sharedLibrary, this.isIndex, this.attributesFile);
        }
        public String getSlotLabel() {
        	if(this.friendlyName != null) {
        		return this.friendlyName;
        	} else {
        		return this.slotNr + this.libName + this.isIndex;
        	}
        }
        public String getLibName() {
            return this.libName;
        }
    }
    /**
     * Unload if last active token on slot
     * @throws LoginException 
     */
    public void logoutFromSlotIfNoTokensActive() {
        final Iterator<Integer> iTokens = this.tokenids.iterator();
        while( iTokens.hasNext() ) {
            if ( tokenMap.get(iTokens.next()).isActive() ) {
                return;
            }
        }
        if ( this.provider instanceof AuthProvider ) {
            try {
                ((AuthProvider)this.provider).logout();
                log.debug("P11 session terminated for \""+this+"\".");
            } catch (LoginException e) {
                log.warn("Not possible to logout from P11 Session. HW problems?", e);
            }
        } else {
            log.warn("Not possible to logout from P11 provider '"+this+"'. It is not implementing '"+AuthProvider.class.getCanonicalName()+"'.");
        }
    }
    /**
     * @return  the provider of the slot.
     */
    public Provider getProvider() {
        return this.provider;
    }
    /**
     * @return  the provider of the slot.
     * @throws CryptoTokenOfflineException
     */
    private synchronized Provider createProvider() throws CryptoTokenOfflineException {
        final Provider tmpProvider;
        while ( this.isSettingProvider ) {
            try {
                this.wait();
            } catch (InterruptedException e1) {
                log.fatal("This should never happened", e1);
            }
        }
        try {
            this.isSettingProvider = true;
            if ( this.slotNr!=null && this.sharedLibrary!=null ) {
                tmpProvider = KeyTools.getP11Provider(this.slotNr, this.sharedLibrary,
                                                        this.isIndex, this.attributesFile);
            } else if ( this.sunP11ConfigFileName!=null ) {
                tmpProvider = KeyTools.getSunP11Provider(new FileInputStream(this.sunP11ConfigFileName));
            } else {
                throw new Error("Should never happen.");
            }
        } catch (IOException e) {
            final CryptoTokenOfflineException e2 = new CryptoTokenOfflineException("Not possible to create provider. See cause.");
            e2.initCause(e);
            throw e2;
        } finally {
            this.isSettingProvider = false;
            this.notifyAll();
        }
        if ( tmpProvider==null ) {
            throw new CryptoTokenOfflineException("Provider is null");
        }
        if ( Security.getProvider(tmpProvider.getName())!=null ) {
            Security.removeProvider(tmpProvider.getName());
        }
        Security.addProvider( tmpProvider );
        if (log.isDebugEnabled()) {
        	log.debug("Provider successfully added: "+tmpProvider);
        }
        return tmpProvider;
    }
}
