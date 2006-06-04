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

package org.ejbca.core.model.ca.catoken;

import java.util.Collection;
import java.util.Hashtable;

import org.apache.log4j.Logger;


/**
 * Class managing available Hard CA Tokens and instansiated CA Tokens. 
 * Each HardCaToken plug-in should register itself by using the method register.
 * The CA keeps a registry of CA tokens created here.
 * 
 * @version $Id: HardCATokenManager.java,v 1.3 2006-06-04 13:02:43 primelars Exp $
 * 
 */
public class HardCATokenManager {
	
    /** Log4j instance for Base */
    private static transient Logger log = Logger.getLogger(HardCATokenManager.class);

    /** Registry of available hard ca token classes that can be instsiated. */
    private Hashtable availablehardcatokens = new Hashtable();
    /** Registry of CATokens associated with a specific CA, kept so CATokens will not
     * be destroyed when a bean is passivated for example. */
    private Hashtable caTokenRegistry = new Hashtable();

    /** Implementing the Singleton pattern */
    private static HardCATokenManager instance = null;

    /**
     * Static intialization block used to register all plug-in classes to the manager.
     * All new plug-ins should add a loadClass call with it's classpath to this method.
     */
    static {
        HardCATokenManager.instance().addAvailableHardCAToken("org.ejbca.core.model.ca.catoken.NFastCAToken", "NFastCAToken", false, true);
        HardCATokenManager.instance().addAvailableHardCAToken("se.primeKey.caToken.card.PrimeCAToken", "PrimeCAToken", false, true);
        HardCATokenManager.instance().addAvailableHardCAToken("org.ejbca.core.model.ca.catoken.EracomCAToken", "Eracom", false, true);
        HardCATokenManager.instance().addAvailableHardCAToken("org.ejbca.core.model.ca.catoken.SafeNetLunaCAToken", "SafeNetLunaCAToken", false, true);
        HardCATokenManager.instance().addAvailableHardCAToken("org.ejbca.core.model.ca.catoken.DummyHardCAToken", "DummyHardCAToken", false, false);
        HardCATokenManager.instance().addAvailableHardCAToken("org.ejbca.core.model.ca.catoken.HardCATokenSample", "HardCATokenSample", false, false);
    }

    /** Don't allow external creation of this class, implementing the Singleton pattern. 
     */
    private HardCATokenManager() {}
    
    /** Get the instance of this singleton
     * 
     */
    public synchronized static HardCATokenManager instance() {
        if (instance == null) {
            instance = new HardCATokenManager();
        }
        return instance;
    }
    
    /** Returns a previously registered (using addCAToken) CAToken, or null.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @return The previously added CAToken or null if the token does not exist in the registry.
     */
    public CAToken getCAToken(int caid) {
        return (CAToken)caTokenRegistry.get(new Integer(caid));
    }
    
    /** Adds a CA token to the token registry. If a token already exists for the given CAid, 
     * the old one is removed and replaced with the new. If the token passed is null, an existing token is removed.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @param token the token to be added
     */
    public synchronized void addCAToken(int caid, CAToken token) {
        if (caTokenRegistry.contains(new Integer(caid))) {
            caTokenRegistry.remove(new Integer(caid));
            log.debug("Removed old CA token for CA: "+caid);
        }
        if (token != null) {
            caTokenRegistry.put(new Integer(caid), token);            
            log.debug("Added CA token for CA: "+caid);
        }
    }
    
    
	/**
	 * Method registering a HardCAToken plug-in as available to the system.
	 * 
	 * @param classpath the classpath of the plug-in
	 * @param name the general name used in adminweb-gui.
	 * @param translateable indicates if the name should be translated in adminweb-gui
	 * @param use indicates if this plug-in should be used.
	 * 
	 * @return true if registration went successful, false if the classpath could not be found or the classpath was already registered.
	 */
	public synchronized boolean addAvailableHardCAToken(String classpath, String name, boolean translateable, boolean use) {
	    boolean retval = false;	
	    if (!availablehardcatokens.contains(classpath)) {
	        log.debug("HardCATokenManager registering " + classpath);                
	        if (loadClass(classpath)) {
	            // Add to the available tokens
	            availablehardcatokens.put(classpath, new AvailableHardCAToken(classpath, name, translateable, use));         
	            retval = true;
	            log.debug("Registered " + classpath + " successfully.");                       
	        } else {
                // Normally not an error, since these classes are provided by HSM vendor
	            log.info("Can not register " + classpath + ". This is normally not an error.");
	        }
	    }
	    return retval;
	}
    /**
     * Method loading a class in order to test if it can be instasiated.
     * 
     * @param classpath 
     */
    private boolean loadClass(String classpath){
        try {           
            HardCATokenManager.class.getClassLoader().loadClass(classpath).newInstance();       
        } catch (ClassNotFoundException e) {
            log.info("Class not found: "+classpath); 
            return false;
        } catch (InstantiationException e) {
            log.info("Can not instantiate "+classpath+". "+e.getMessage());
            return false;
        } catch (IllegalAccessException e) {
            log.error("IllegalAccessException: "+classpath);
            return false;
        }    
        return true;
    }
	
	/**
	 * Method returning to the system available HardCATokens
	 * 
	 * @return a Collection (AvailableHardCAToken) of registrered plug-ins.
	 */
	public Collection getAvailableHardCATokens(){
	   return availablehardcatokens.values();	
	}

	/**
	 * Method returning to the available hardcatoken with given classpath.
	 * 
	 * @return the corresponding AvailableHardCAToken or null of classpath couldn't be found
	 */
	public AvailableHardCAToken getAvailableHardCAToken(String classpath){
        if (classpath == null) { return null; }
	    return (AvailableHardCAToken)availablehardcatokens.get(classpath);
	}
	
}
