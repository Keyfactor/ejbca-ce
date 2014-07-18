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
package org.cesecore.keys.token;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;
import org.cesecore.keys.token.p11.exception.NoSuchSlotException;


/**
 * Class managing available Crypto Tokens and instantiated Crypto Tokens. 
 * Each CryptoToken plug-in should register itself by using the method register.
 * 
 * @version $Id$
 */
public class CryptoTokenFactory {
	
    private static transient Logger log = Logger.getLogger(CryptoTokenFactory.class);
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Registry of available hard ca token classes that can be instantiated. */
    private Map<String, AvailableCryptoToken> availabletokens = new HashMap<String, AvailableCryptoToken>();

    /** Implementing the Singleton pattern */
    private static CryptoTokenFactory instance = null;

    /**
     * Static intialization block used to register all plug-in classes to the manager.
     * All new plug-ins should add a loadClass call with it's classpath to this method.
     */
    static {
        /** Can't use class.getName() here because this class is not always available */
        CryptoTokenFactory.instance().addAvailableCryptoToken("se.primeKey.caToken.card.PrimeCAToken", "PrimeCAToken", false, true);
        CryptoTokenFactory.instance().addAvailableCryptoToken(PKCS11CryptoToken.class.getName(), "PKCS#11", false, true);
        CryptoTokenFactory.instance().addAvailableCryptoToken(SoftCryptoToken.class.getName(), "SOFT", true, true);
        CryptoTokenFactory.instance().addAvailableCryptoToken(NullCryptoToken.class.getName(), "Null", false, false);
    }

    /** Don't allow external creation of this class, implementing the Singleton pattern. 
     */
    private CryptoTokenFactory() {}
    
    /** Get the instance of this singleton
     * 
     */
    public synchronized static CryptoTokenFactory instance() {
        if (instance == null) {
            instance = new CryptoTokenFactory();
        }
        return instance;
    }
    
	/**
	 * Method returning to the system available CryptoToken implementations
	 * 
	 * @return a Collection (AvailableCryptoToken) of registered plug-ins.
	 */
	public Collection<AvailableCryptoToken> getAvailableCryptoTokens(){
	   return availabletokens.values();	
	}

	/**
	 * Method returning to the available CryptoToken implementations with given classpath.
	 * 
	 * @return the corresponding AvailableCryptoToken or null of classpath couldn't be found
	 */
	public AvailableCryptoToken getAvailableCryptoToken(String classname){
        if (classname == null) { return null; }
	    return (AvailableCryptoToken)availabletokens.get(classname);
	}
	
	/**
	 * Method registering a crypto token plug-in as available to the system.
	 * 
	 * @param classname the full classname of the crypto token implementation class
	 * @param name the general name used in adminweb-gui.
	 * @param translateable indicates if the name should be translated in adminweb-gui
	 * @param use indicates if this plug-in should be used.
	 * 
	 * @return true if registration went successful, false if the classpath could not be found or the classpath was already registered.
	 */
	public synchronized boolean addAvailableCryptoToken(String classname, String name, boolean translateable, boolean use) {
		if (log.isTraceEnabled()) {
			log.trace(">addAvailableCryptoToken: "+classname);
		}
		boolean retval = false;	
		if (!availabletokens.containsKey(classname)) {
			log.debug("CryptoTokenFactory adding available crypto token " + classname);                
			if (loadClass(classname)) {
				// Add to the available tokens
				availabletokens.put(classname, new AvailableCryptoToken(classname, name, translateable, use));         
				retval = true;
				log.debug("Registered " + classname + " successfully.");                       
			} else {
				// Normally not an error, since these classes are provided by HSM vendor
				String msg = intres.getLocalizedMessage("token.inforegisterclasspath", classname);
				log.info(msg);
			}
		}			
		if (log.isTraceEnabled()) {
			log.trace("<addAvailableCryptoToken: "+classname);
		}
		return retval;
	}
    /**
     * Method loading a class in order to test if it can be instansiated.
     * 
     * @param classname 
     */
    private boolean loadClass(String classname){
        try {           
        	Thread.currentThread().getContextClassLoader().loadClass(classname).newInstance();       
        } catch (ClassNotFoundException e) {
			String msg = intres.getLocalizedMessage("token.classnotfound", classname);
            log.info(msg); 
            return false;
        } catch (InstantiationException e) {
			String msg = intres.getLocalizedMessage("token.errorinstansiate", classname, e.getMessage());
            log.info(msg);
            return false;
        } catch (IllegalAccessException e) {
            log.error("IllegalAccessException: "+classname, e);
            return false;
        } catch (NoClassDefFoundError e) {
            // This happens more rarely and should be flagged as an error
            log.error("NoClassDefFoundError: "+classname, e);
            return false;        	
        }
        return true;
    }
    
    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken
     * 
     * @param classname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param id id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static final CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int id,
            String tokenName) throws NoSuchSlotException {
        final String classname;
        if (inClassname != null) {
            classname = inClassname;
        } else {
            classname = NullCryptoToken.class.getName();
            log.info("This must be an imported CA that is being upgraded. Use NullCryptoToken.");
        }
        final CryptoToken token = createTokenFromClass(classname);
        if (token == null) {
            log.error("No token. Classpath=" + classname);
            return null;
        }
        try {
            token.init(properties, data, id);
        } catch (NoSuchSlotException e) {
            if (!Boolean.valueOf(properties.getProperty(CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY, "false"))) {
                throw e;
            }
        } catch (Exception e) {
            log.error("Error initializing Crypto Token. Classpath=" + classname, e);
        }
        token.setTokenName(tokenName);
        return token;
    }
    
    private static final CryptoToken createTokenFromClass(final String classpath) {
    	try{				
    		Class<?> implClass = Class.forName(classpath);
    		Object obj = implClass.newInstance();
    		return (CryptoToken) obj;
    	}catch(Throwable e){
    		log.error("Error contructing Crypto Token (setting to null). Classpath="+classpath, e);
    		return null;
    	}
    }
}
