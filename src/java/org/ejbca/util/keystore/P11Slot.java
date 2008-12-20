package org.ejbca.util.keystore;

import java.io.File;
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

    public interface P11SlotUser {
        boolean deactivate() throws Exception;
        boolean isActive();
    }
    private final static Map<String,P11Slot> slotMap = new HashMap<String, P11Slot>();
    private final static Map<String,Set<P11Slot>> libMap = new HashMap<String, Set<P11Slot>>();
    final private String slotNr;
    final private String sharedLibrary;
    final private boolean isIndex;
    final private Set<P11SlotUser> caTokens;
    private String atributesFile;
    private Provider provider;
    private boolean isSettingProvider = false;
    private P11Slot(String _slotNr, String _sharedLibrary, boolean _isIndex ) {
        this.slotNr = _slotNr;
        this.sharedLibrary = _sharedLibrary;
        this.isIndex = _isIndex;
        this.caTokens = new HashSet<P11SlotUser>();
    }
    /* (non-Javadoc)
     * @see java.lang.Object#toString()
     */
    @Override
    public String toString() {
        return "P11 slot "+(this.isIndex ? "index ":"#")+this.slotNr+" using library "+this.sharedLibrary+'.';
    }
    public void reset() {
        final Iterator<P11Slot> i = libMap.get(new File(P11Slot.this.sharedLibrary).getName()).iterator();
        while( i.hasNext() ) {
            Iterator<P11SlotUser> i2 = i.next().caTokens.iterator();
            while( i2.hasNext() )
                try {
                    i2.next().deactivate();
                } catch (Exception e) {
                    log.error("Not possible to deactivate token.", e);
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
     * @throws IOException
     */
    static public P11Slot getInstance(String slotNr, String sharedLibrary, boolean isIndex, 
                                      String _atributesFile, P11SlotUser token) {
        final String libName = new File(sharedLibrary).getName();
        final String slotLabel = slotNr + libName + isIndex;
        P11Slot slot = slotMap.get(slotLabel);
        if (slot==null) {
            slot = new P11Slot(slotNr, sharedLibrary, isIndex);
            slotMap.put(slotLabel, slot);
            Set<P11Slot> libSet = libMap.get(libName);
            if (libSet==null) {
                libSet=new HashSet<P11Slot>();
                libMap.put(libName, libSet);
            }
            libSet.add(slot);
        }
        slot.atributesFile = _atributesFile;
        slot.caTokens.add(token);
        return slot;
    }
    /**
     * Unload if last active token on slot
     * @throws LoginException 
     */
    public void removeProviderIfNoTokensActive() throws LoginException {
        if (this.provider==null)
            return;
        final Iterator<P11SlotUser> iTokens = this.caTokens.iterator();
        while( iTokens.hasNext() ) {
            if ( iTokens.next().isActive() )
                return;
        }
        System.runFinalization();
        Security.removeProvider(this.provider.getName());
        ((AuthProvider)this.provider).logout();
        this.provider.clear();
        this.provider = null;
        System.runFinalization();
    }
    /**
     * @return  the provider of the slot.
     * @throws CATokenOfflineException
     */
    public synchronized Provider getProvider() throws CATokenOfflineException {
        while ( this.isSettingProvider )
            try {
                this.wait();
            } catch (InterruptedException e1) {
                log.fatal("This should never happend", e1);
            }
        if ( this.provider!=null )
            return this.provider;
        try {
            this.isSettingProvider = true;
            System.runFinalization();
            this.provider = KeyTools.getP11Provider(this.slotNr, this.sharedLibrary,
                                                    this.isIndex, this.atributesFile);
        } catch (IOException e) {
            final CATokenOfflineException e2 = new CATokenOfflineException("Not possible to create provider. See cause.");
            e2.initCause(e);
            throw e2;
        } finally {
            this.isSettingProvider = false;
            this.notifyAll();
        }
        if ( this.provider==null )
            throw new CATokenOfflineException("Provider is null");
        log.debug("Provider successfully added: "+this.provider);
        System.runFinalization();
        return this.provider;
    }
}
