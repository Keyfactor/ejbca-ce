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
import org.ejbca.core.model.InternalResources;


/**
 * Class managing available Hard CA Tokens and instansiated CA Tokens. 
 * Each HardCaToken plug-in should register itself by using the method register.
 * The CA keeps a registry of CA tokens created here.
 * 
 * @version $Id$
 * 
 */
public class CATokenManager {
	
    /** Log4j instance for Base */
    private static transient Logger log = Logger.getLogger(CATokenManager.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Registry of available hard ca token classes that can be instsiated. */
    private Hashtable availablehardcatokens = new Hashtable();
    /** Registry of CATokens associated with a specific CA, kept so CATokens will not
     * be destroyed when a bean is passivated for example. */
    private Hashtable caTokenRegistry = new Hashtable();

    /** Implementing the Singleton pattern */
    private static CATokenManager instance = null;

    /**
     * Static intialization block used to register all plug-in classes to the manager.
     * All new plug-ins should add a loadClass call with it's classpath to this method.
     */
    static {
        CATokenManager.instance().addAvailableCAToken(NFastCAToken.class.getName(), "NFastCAToken", false, true);
        /** Can't use class.getName() here because this class is not always available */
        CATokenManager.instance().addAvailableCAToken("se.primeKey.caToken.card.PrimeCAToken", "PrimeCAToken", false, true);
        CATokenManager.instance().addAvailableCAToken(EracomCAToken.class.getName(), "Eracom", false, true);
        CATokenManager.instance().addAvailableCAToken(PKCS11CAToken.class.getName(), "PKCS#11", false, true);
        /** Can't use class.getName() here because this class is not always available */
        CATokenManager.instance().addAvailableCAToken("org.ejbca.core.model.ca.catoken.SafeNetLunaCAToken", "SafeNetLunaCAToken", false, true);
        CATokenManager.instance().addAvailableCAToken(SoftCAToken.class.getName(), "SOFT", true, true);
        CATokenManager.instance().addAvailableCAToken(NullCAToken.class.getName(), "Null", false, false);
    }

    /** Don't allow external creation of this class, implementing the Singleton pattern. 
     */
    private CATokenManager() {}
    
    /** Get the instance of this singleton
     * 
     */
    public synchronized static CATokenManager instance() {
        if (instance == null) {
            instance = new CATokenManager();
        }
        return instance;
    }
    
    /** Returns a previously registered (using addCAToken) CAToken, or null.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @return The previously added CAToken or null if the token does not exist in the registry.
     */
    public CATokenContainer getCAToken(int caid) {
        return (CATokenContainer)caTokenRegistry.get(new Integer(caid));
    }
    
    /** Adds a CA token to the token registry. If a token already exists for the given CAid, 
     * the old one is removed and replaced with the new. If the token passed is null, an existing token is removed.
     * 
     * @param caid the id of the CA whose CAToken you want to fetch.
     * @param token the token to be added
     */
    public synchronized void addCAToken(int caid, CATokenContainer token) {
        if (caTokenRegistry.containsKey(new Integer(caid))) {
            caTokenRegistry.remove(new Integer(caid));
            log.debug("Removed old CA token for CA: "+caid);
        }
        if (token != null) {
            caTokenRegistry.put(new Integer(caid), token);            
            log.debug("Added CA token for CA: "+caid);
        }
    }

    /** Removes a CA token from the cache to force an update the next time the CA is read
     * 
     */
    public synchronized void removeCAToken(int caid) {
        if (caTokenRegistry.containsKey(new Integer(caid))) {
        	caTokenRegistry.remove(new Integer(caid));
            log.debug("Removed old CA token from registry: "+caid);
        }
    }

    /** Remove all CA tokens
     */
    public synchronized void removeAll() {
    	caTokenRegistry = new Hashtable();
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
	public synchronized boolean addAvailableCAToken(String classpath, String name, boolean translateable, boolean use) {
		if (log.isTraceEnabled()) {
			log.trace(">addAvailableCAToken: "+classpath);
		}
		boolean retval = false;	
		if (!availablehardcatokens.containsKey(classpath)) {
			log.debug("CATokenManager registering " + classpath);                
			if (loadClass(classpath)) {
				// Add to the available tokens
				availablehardcatokens.put(classpath, new AvailableCAToken(classpath, name, translateable, use));         
				retval = true;
				log.debug("Registered " + classpath + " successfully.");                       
			} else {
				// Normally not an error, since these classes are provided by HSM vendor
				String msg = intres.getLocalizedMessage("catoken.inforegisterclasspath", classpath);
				log.info(msg);
			}
		}			
		if (log.isTraceEnabled()) {
			log.trace("<addAvailableCAToken: "+classpath);
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
        	Thread.currentThread().getContextClassLoader().loadClass(classpath).newInstance();       
        } catch (ClassNotFoundException e) {
			String msg = intres.getLocalizedMessage("catoken.classnotfound", classpath);
            log.info(msg); 
            return false;
        } catch (InstantiationException e) {
			String msg = intres.getLocalizedMessage("catoken.errorinstansiate", classpath, e.getMessage());
            log.info(msg);
            return false;
        } catch (IllegalAccessException e) {
            log.error("IllegalAccessException: "+classpath, e);
            return false;
        } catch (NoClassDefFoundError e) {
            // This happens more rarely and should be flagged as an error
            log.error("NoClassDefFoundError: "+classpath, e);
            return false;        	
        }
        return true;
    }
	
	/**
	 * Method returning to the system available HardCATokens
	 * 
	 * @return a Collection (AvailableCAToken) of registrered plug-ins.
	 */
	public Collection getAvailableCATokens(){
	   return availablehardcatokens.values();	
	}

	/**
	 * Method returning to the available hardcatoken with given classpath.
	 * 
	 * @return the corresponding AvailableCAToken or null of classpath couldn't be found
	 */
	public AvailableCAToken getAvailableCAToken(String classpath){
        if (classpath == null) { return null; }
	    return (AvailableCAToken)availablehardcatokens.get(classpath);
	}
	
}
