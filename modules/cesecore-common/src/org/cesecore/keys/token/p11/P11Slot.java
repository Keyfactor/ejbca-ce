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
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

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
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(P11Slot.class);

    /**
     * Used for library key map when a sun configuration file is used to specify a token (slot). In this case only one lib could be used.
     */
    private static final String ONLY_ONE = "onlyOne";
    
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    private final static Map<String,P11Slot> slotMap = new HashMap<String, P11Slot>();
    private final static Set<String> slotsBeingCreated = new HashSet<String>();
    private final static Map<String,Set<P11Slot>> libMap = new HashMap<String, Set<P11Slot>>();
    private final static Map<Integer, P11SlotUser> tokenMap = new HashMap<Integer, P11SlotUser>();
    private final String slotNr;
    private final Pkcs11SlotLabelType slotLabelType;
    private final String sharedLibrary;
    private final String attributesFile;
    private final Set<Integer> tokenids = new HashSet<Integer>();
    private final String sunP11ConfigFileName;
    private final Provider provider;
    private boolean isSettingProvider = false;
    
    private P11Slot(String _slotNr, Pkcs11SlotLabelType slotLabelType, String _sharedLibrary, String _attributesFile) throws CryptoTokenOfflineException, NoSuchSlotException {
        this.slotNr = _slotNr;
        this.sharedLibrary = _sharedLibrary;
        this.attributesFile = _attributesFile;
        this.sunP11ConfigFileName = null;
        this.slotLabelType = slotLabelType;
        this.provider = createProvider();
       
    }
    private P11Slot( String configFileName ) throws CryptoTokenOfflineException, NoSuchSlotException {
        this.sunP11ConfigFileName = configFileName;
        this.slotNr = null;
        this.sharedLibrary = null;
        this.attributesFile = null;
        this.slotLabelType = Pkcs11SlotLabelType.SUN_FILE;
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
        return "P11 slot "+this.slotNr+" using library "+this.sharedLibrary+'.';
    }

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
    public static P11Slot getInstance(String slotLabel, String sharedLibrary, Pkcs11SlotLabelType slotLabelType, 
                                      String attributesFile, P11SlotUser token, int id) throws CryptoTokenOfflineException, NoSuchSlotException {       
        return getInstance(null, slotLabel, sharedLibrary, slotLabelType, attributesFile, token, id);
    }
    
    
    
    /**
     * Get P11 slot instance. Only one instance (provider) will ever be created for each slot regardless of how many times this method is called.
     * @param friendlyName name to identify the instance
     * @param slotLabel the labeling of the slot, regardless of label type. 
     * @param sharedLibrary file path of shared
     * @param slotLabelType The type of the label. May be a slot number [0...9]*, slot index i[0...9]* or a label. 
     * @param attributesFile Attributes file. Optional. Set to null if not used
     * @param token Token that should use this object
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return P11Slot
     * @throws CryptoTokenOfflineException if token can not be activated
     * @throws NoSuchSlotException if no slot by the given label could be found
     */
    public static P11Slot getInstance(String friendlyName, String slotLabel, String sharedLibrary, Pkcs11SlotLabelType slotLabelType, 
                                      String attributesFile, P11SlotUser token, int id) throws CryptoTokenOfflineException, NoSuchSlotException {
        if (sharedLibrary == null) {
            throw new IllegalArgumentException("sharedLibrary = null");
        }
        if (log.isDebugEnabled()) {
            log.debug("slotlabel: "+slotLabel);
            log.debug("sharedlib: "+sharedLibrary);
            log.debug("slotlabeltype: "+slotLabelType);
            log.debug("attributesFile: " +attributesFile);
            log.debug("id: "+id);
        	log.debug("P11Slot.getInstance(): '"+slotLabel+"', '"+sharedLibrary+"', "+(slotLabelType == null ? "null" : slotLabelType.toString())+", '"+attributesFile+"', "+id);
        }
        return getInstance(new SlotDataParam(friendlyName, slotLabel, sharedLibrary, slotLabelType, attributesFile), token, id);
    }
    /**
     * As {@link #getInstance(String, String, boolean, String, org.ejbca.util.keystore.P11Slot.P11SlotUser)} but is using config file instead parameters. Do only use this method if the P11 shared library is ony specified in this config file.
     * @param configFileName name of config file
     * @param token Token that should use this object.
     * @param id unique ID of the user of the token. For EJBCA this is the caid. For the OCSP responder this is fixed since then there is only one user.
     * @return a new P11Slot instance
     * @throws CryptoTokenOfflineException
     * @throws NoSuchSlotException if no slot defined by the label in configFileName could be found.
     */
    public static P11Slot getInstance(String configFileName, P11SlotUser token, int id) throws CryptoTokenOfflineException, NoSuchSlotException {
        return getInstance(new SlotDataConfigFile(configFileName), token, id);
    }
    private static P11Slot getInstance(SlotData data, P11SlotUser token, int id) throws CryptoTokenOfflineException, NoSuchSlotException {
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
                            throw new RuntimeException( "This should never happen.", e);
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
    private static interface SlotData {
        P11Slot getNewP11Slot() throws CryptoTokenOfflineException, NoSuchSlotException;
        String getSlotLabel();
        String getLibName();
    }
    private static class SlotDataConfigFile implements SlotData {
        private final String configFileName;
        SlotDataConfigFile(String _configFileName) {
            this.configFileName = _configFileName;
        }
        public String getLibName() {
            return ONLY_ONE;
        }
        public P11Slot getNewP11Slot() throws CryptoTokenOfflineException, NoSuchSlotException {
            return new P11Slot(this.configFileName);
        }
        public String getSlotLabel() {
            return new File(this.configFileName).getName();
        }
    }
    
    private static class SlotDataParam implements SlotData {
    	private final String friendlyName;
        private final String slotLabel;
        private final String sharedLibrary;
        private final String libName;
        private final Pkcs11SlotLabelType slotLabelType;
        private final String attributesFile;
        
        public SlotDataParam(String _friendlyName, String slotLabel, String _sharedLibrary, Pkcs11SlotLabelType slotLabelType, 
                      String _attributesFile) {
            this.slotLabel = slotLabel;
            this.sharedLibrary = _sharedLibrary;
            this.slotLabelType = slotLabelType;
            this.attributesFile = _attributesFile;
            this.libName = new File(this.sharedLibrary).getName();
            this.friendlyName = _friendlyName;
        }
        
        public P11Slot getNewP11Slot() throws CryptoTokenOfflineException, NoSuchSlotException {     
            return new P11Slot(this.slotLabel, this.slotLabelType,  this.sharedLibrary, this.attributesFile);
        }
        
        public String getSlotLabel() {
        	if(this.friendlyName != null) {
        		return this.friendlyName;
        	} else {
        		return this.slotLabel + this.libName + this.slotLabelType.toString();
        	}
        }
        
        public String getLibName() {
            return this.libName;
        }
    }
    /**
     * Unload if last active token on slot
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
     * @throws NoSuchSlotException 
     */
    private synchronized Provider createProvider() throws CryptoTokenOfflineException, NoSuchSlotException {
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
                tmpProvider = Pkcs11SlotLabel.getP11Provider(this.slotNr, slotLabelType, this.sharedLibrary,
                                                        this.attributesFile);
            } else if ( this.sunP11ConfigFileName!=null ) {
                tmpProvider = new Pkcs11SlotLabel(Pkcs11SlotLabelType.SUN_FILE, null).getProvider(this.sunP11ConfigFileName, null, null);
            } else {
                throw new IllegalStateException("Should never happen.");
            }
        } finally {
            this.isSettingProvider = false;
            this.notifyAll();
        }
        if ( tmpProvider==null ) {
            throw new NoSuchSlotException("Slot labeled " + slotNr + " could not be located.");
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
