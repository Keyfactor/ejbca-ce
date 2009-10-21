package org.ejbca.util.keystore;

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
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;

public class P11Slot {
    /** Log4j instance */
    private static final Logger log = Logger.getLogger(P11Slot.class);

    /**
     * All users of the {@link P11Slot} slot must implement this interface.
     * The user may decide whether deactivation is allowed or not. Deactivation of a user is done when the {@link P11Slot} object wants to reset P11 session (disconnect and reconnect).
     * <p>
     * If deactivation is allowed and {@link #deactivate()} called the user should:<br>
     * Deactivate itself (answer false to {@link #isActive()}) and call {@link P11Slot#removeProviderIfNoTokensActive()}
     * Then {@link P11Slot#getProvider()} must be called before using the provider again.
     * </p><p>
     * If deactivation is not allowed then the user may just continue to answer true to {@link #isActive()}.
     * </p>
     */
    public interface P11SlotUser {
        /**
         * Called by the {@link P11Slot} when resetting the slot.
         * @return false if any problem with the deactivation. Otherwise true.
         * @throws Exception
         */
        boolean deactivate() throws Exception;
        /**
         * The user should return true if not accepting a slot reset.
         * @return true if the slot is being used.
         */
        boolean isActive();
    }
    private final static Map<String,P11Slot> slotMap = new HashMap<String, P11Slot>();
    private final static Map<String,Set<P11Slot>> libMap = new HashMap<String, Set<P11Slot>>();
    final private String slotNr;
    final private String sharedLibrary;
    final private String attributesFile;
    final private boolean isIndex;
    final private Set<P11SlotUser> caTokens;
    final private String sunP11ConfigFileName;
    final private Provider provider;
    private boolean isSettingProvider = false;
    private P11Slot(String _slotNr, String _sharedLibrary, boolean _isIndex, String _attributesFile) throws CATokenOfflineException {
        this.slotNr = _slotNr;
        this.sharedLibrary = _sharedLibrary;
        this.isIndex = _isIndex;
        this.attributesFile = _attributesFile;
        this.caTokens = new HashSet<P11SlotUser>();
        this.sunP11ConfigFileName = null;
        this.provider = createProvider();
    }
    private P11Slot( String configFileName ) throws CATokenOfflineException {
        this.sunP11ConfigFileName = configFileName;
        this.slotNr = null;
        this.sharedLibrary = null;
        this.isIndex = false;
        this.attributesFile = null;
        this.caTokens = new HashSet<P11SlotUser>();
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
        final Iterator<P11Slot> i = libMap.get(mapName).iterator();
        while( i.hasNext() ) {
            Iterator<P11SlotUser> i2 = i.next().caTokens.iterator();
            while( i2.hasNext() ) {
                try {
                    i2.next().deactivate();
                } catch (Exception e) {
                    log.error("Not possible to deactivate token.", e);
                }
            }
        }
    }
    /**
     * Get P11 slot instance. Only one instance will ever be created for each slot regardles of how many times this method is called.
     * @param slotNr number of the slot
     * @param sharedLibrary file path of shared 
     * @param isIndex true if not slot number but index in slot list
     * @param _atributesFile Atributes file. Optional. Set to null if not used
     * @param token Token that should use this object
     * @return The instance.
     * @throws CATokenOfflineException if CA token can not be activated, IllegalArgumentException if sharedLibrary is null.
     */
    static public P11Slot getInstance(String slotNr, String sharedLibrary, boolean isIndex, 
                                      String attributesFile, P11SlotUser token) throws CATokenOfflineException {
    	if (sharedLibrary == null) {
    		throw new IllegalArgumentException("sharedLibrary = null");
    	}
        final String libName = new File(sharedLibrary).getName();
        final String slotLabel = slotNr + libName + isIndex;
        P11Slot slot = slotMap.get(slotLabel);
        if (slot==null) {
            slot = new P11Slot(slotNr, sharedLibrary, isIndex, attributesFile);
            slotMap.put(slotLabel, slot);
            Set<P11Slot> libSet = libMap.get(libName);
            if (libSet==null) {
                libSet=new HashSet<P11Slot>();
                libMap.put(libName, libSet);
            }
            libSet.add(slot);
        }
        slot.caTokens.add(token);
        return slot;
    }
    /**
     * As {@link #getInstance(String, String, boolean, String, org.ejbca.util.keystore.P11Slot.P11SlotUser)} but is using config file instead parameters.
     * @param configFileName name of config file
     * @param token Token that should use this object.
     * @return
     * @throws CATokenOfflineException 
     */
    static public P11Slot getInstance(String configFileName, P11SlotUser token) throws CATokenOfflineException {
        final String slotLabel = new File(configFileName).getName();
        P11Slot slot = slotMap.get(slotLabel);
        if (slot==null) {
            slot = new P11Slot(configFileName);
            slotMap.put(slotLabel, slot);
            Set<P11Slot> libSet = libMap.get(ONLY_ONE);
            if (libSet==null) {
                libSet=new HashSet<P11Slot>();
                libMap.put(ONLY_ONE, libSet);
            }
            libSet.add(slot);
        }
        slot.caTokens.add(token);
        return slot;
    }
    /**
     * Unload if last active token on slot
     * @throws LoginException 
     */
    public void removeProviderIfNoTokensActive() {
        final Iterator<P11SlotUser> iTokens = this.caTokens.iterator();
        while( iTokens.hasNext() ) {
            if ( iTokens.next().isActive() ) {
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
     * @throws CATokenOfflineException
     */
    public Provider getProvider() {
        return this.provider;
    }
    /**
     * @return  the provider of the slot.
     * @throws CATokenOfflineException
     */
    private synchronized Provider createProvider() throws CATokenOfflineException {
        final Provider tmpProvider;
        while ( this.isSettingProvider ) {
            try {
                this.wait();
            } catch (InterruptedException e1) {
                log.fatal("This should never happend", e1);
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
                throw new Error("Should never happend.");
            }
        } catch (IOException e) {
            final CATokenOfflineException e2 = new CATokenOfflineException("Not possible to create provider. See cause.");
            e2.initCause(e);
            throw e2;
        } finally {
            this.isSettingProvider = false;
            this.notifyAll();
        }
        if ( tmpProvider==null )
            throw new CATokenOfflineException("Provider is null");
        if ( Security.getProvider(tmpProvider.getName())==null ) {
            Security.addProvider( tmpProvider );
        }
        log.debug("Provider successfully added: "+tmpProvider);
        return tmpProvider;
    }
}
