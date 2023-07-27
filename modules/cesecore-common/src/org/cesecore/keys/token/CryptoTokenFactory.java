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

import java.lang.reflect.InvocationTargetException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import com.google.common.base.Preconditions;
import com.keyfactor.util.keys.token.CryptoToken;
import com.keyfactor.util.keys.token.pkcs11.NoSuchSlotException;

import org.apache.log4j.Logger;
import org.cesecore.internal.InternalResources;


/**
 * Class managing available Crypto Tokens and instantiated Crypto Tokens. 
 * Each CryptoToken plug-in should register itself by using the method register.
 * 
 * @version $Id$
 */
public class CryptoTokenFactory {
	

    private static transient Logger log = Logger.getLogger(CryptoTokenFactory.class);
    
    // Used for references where EE version may not be available
    public static final String JACKNJI_SIMPLE_NAME = "Pkcs11NgCryptoToken";
    public static final String JACKNJI_NAME = "org.cesecore.keys.token.p11ng.cryptotoken.Pkcs11NgCryptoToken";
    public static final String PRIME_CA_TOKEN_SIMPLE_NAME = "PrimeCAToken";
    public static final String PRIME_CA_TOKEN_NAME = "se.primeKey.caToken.card.PrimeCAToken";
    public static final String AWSKMS_SIMPLE_NAME = "AWSKMSCryptoToken";
    public static final String AWSKMS_NAME = "org.ejbca.keys.token.AWSKMSCryptoToken";
    public static final String FORTANIX_NAME = "org.ejbca.keys.token.FortanixCryptoToken";
    public static final String FORTANIX_SIMPLE_NAME = "FortanixCryptoToken";


    /** Registry of available hard ca token classes that can be instantiated. */
    private Map<String, AvailableCryptoToken> availabletokens = new HashMap<>(4);

    /** Implementing the Singleton pattern */
    private static CryptoTokenFactory instance = null;

    /** Don't allow external creation of this class, implementing the Singleton pattern. */
    private CryptoTokenFactory() {}
    
    /** Get the instance of this singleton */
    public synchronized static CryptoTokenFactory instance() {
        if (instance == null) {
            instance = new CryptoTokenFactory();
            /** Can't use class.getName() here because this class is not always available */
            instance.addAvailableCryptoToken(PRIME_CA_TOKEN_NAME, PRIME_CA_TOKEN_SIMPLE_NAME, false, true);
            instance.addAvailableCryptoToken(PKCS11CryptoToken.class.getName(), "PKCS#11", false, true);
            instance.addAvailableCryptoToken(SoftCryptoToken.class.getName(), "SOFT", true, true);
            instance.addAvailableCryptoToken(NullCryptoToken.class.getName(), "Null", false, false);
            instance.addAvailableCryptoToken(AzureCryptoToken.class.getName(), "Azure Key Vault", false, true);
            // Enterprise only. May not be available don't reference class.
            instance.addAvailableCryptoToken(FORTANIX_NAME, "Fortanix DSM", false, true);
            // Enterprise only. May not be available don't reference class.
            instance.addAvailableCryptoToken(AWSKMS_NAME, "AWS KMS", false, true);
            // Enterprise only. May not be available don't reference class.
            instance.addAvailableCryptoToken(JACKNJI_NAME, "PKCS#11 NG", false, true); 
        }
        return instance;
    }
    
	/**
	 * Method returning to the system available CryptoToken implementations
	 * 
	 * @return a Collection (AvailableCryptoToken) of registered plug-ins.
	 */
	public Collection<AvailableCryptoToken> getAvailableCryptoTokens() {
	    return availabletokens.values();	
	}

	/**
	 * Method returning to the available CryptoToken implementations with given classpath.
	 * 
	 * @return the corresponding AvailableCryptoToken or null of classpath couldn't be found
	 */
	public AvailableCryptoToken getAvailableCryptoToken(final String classname) {
        if (classname == null) {
            return null;
        }
	    return availabletokens.get(classname);
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
	/*package*/ boolean addAvailableCryptoToken(final String classname, final String name, final boolean translateable, final boolean use) {
		if (log.isTraceEnabled()) {
			log.trace(">addAvailableCryptoToken: "+classname);
		}
		boolean retval = false;	
		if (!availabletokens.containsKey(classname)) {
		    if (log.isDebugEnabled()) {
	            log.debug("CryptoTokenFactory adding available crypto token " + classname);                
		    }
			if (loadClass(classname)) {
				// Add to the available tokens
				availabletokens.put(classname, new AvailableCryptoToken(classname, name, translateable, use));         
				retval = true;
	            if (log.isDebugEnabled()) {
	                log.debug("Registered " + classname + " successfully.");                       
	            }
			} else {
				// Normally not an error, since these classes are provided by HSM vendor
				log.info(InternalResources.getInstance().getLocalizedMessage("token.inforegisterclasspath", classname));
			}
		}			
		if (log.isTraceEnabled()) {
			log.trace("<addAvailableCryptoToken: "+classname);
		}
		return retval;
	}

	/**
     * Method loading a class in order to test if it can be instantiated.
     * 
     * @param classname 
     */
    private boolean loadClass(final String classname){
        try {           
        	Thread.currentThread().getContextClassLoader().loadClass(classname).getDeclaredConstructor().newInstance();       
            return true;
        } catch (ClassNotFoundException e) {
            log.info(InternalResources.getInstance().getLocalizedMessage("token.classnotfound", classname)); 
        } catch (InstantiationException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException e) {
            log.info(InternalResources.getInstance().getLocalizedMessage("token.errorinstansiate", classname, e.getMessage()));
        } catch (IllegalAccessException e) {
            log.error("IllegalAccessException: "+classname, e);
        } catch (NoClassDefFoundError e) {
            // This happens more rarely and should be flagged as an error
            log.error("NoClassDefFoundError: "+classname, e);
        } 
        return false;
    }
    
    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static final CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName) throws NoSuchSlotException {
        final boolean allowNonExistingSlot = Boolean.valueOf(properties.getProperty(CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY, Boolean.FALSE.toString()));
        return createCryptoToken(inClassname, properties, data, cryptoTokenId, tokenName, allowNonExistingSlot);
    }
    
    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @param keyAndCertFinder an object that can find public key token authentication credentials from the config
     * @throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static final CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName, KeyAndCertFinder keyAndCertFinder) throws NoSuchSlotException {
        final boolean allowNonExistingSlot = Boolean.valueOf(properties.getProperty(CryptoToken.ALLOW_NONEXISTING_SLOT_PROPERTY, Boolean.FALSE.toString()));
        return createCryptoToken(inClassname, properties, data, cryptoTokenId, tokenName, allowNonExistingSlot, keyAndCertFinder);
    }

    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @param allowNonExistingSlot if the NoSuchSlotException should be used
     * @throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static final CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName, boolean allowNonExistingSlot) throws NoSuchSlotException {
        return createCryptoToken(inClassname, properties, data, cryptoTokenId, tokenName, allowNonExistingSlot, null);
    }

    /** Creates a crypto token using reflection to construct the class from classname and initializing the CryptoToken, potentially enabling public key authentication to the token.
     * 
     * @param inClassname the full classname of the crypto token implementation class
     * @param properties properties passed to the init method of the CryptoToken
     * @param data byte data passed to the init method of the CryptoToken
     * @param cryptoTokenId id passed to the init method of the CryptoToken, the id is user defined and not used internally for anything but logging.
     * @param tokenName user friendly identifier
     * @param allowNonExistingSlot if the NoSuchSlotException should be used
     * @param keyAndCertFinder If specified, an object that can take a name from properties and find a key/cert pair.  Currently, only relevant for Azure Key Vault.
     * throws NoSuchSlotException if no slot as defined in properties could be found.
     */
    public static CryptoToken createCryptoToken(final String inClassname, final Properties properties, final byte[] data, final int cryptoTokenId,
            String tokenName, boolean allowNonExistingSlot, KeyAndCertFinder keyAndCertFinder) throws NoSuchSlotException {
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
        
        // AzureCryptoToken can potentially take a key binding name as its authentication method.  Set its member that can find the key binding.
        if (token instanceof AzureCryptoToken) {
            Preconditions.checkNotNull(keyAndCertFinder, "keyAndCertFinder is null when constructing an AzureCryptoToken");
            ((AzureCryptoToken) token).setAuthKeyProvider(keyAndCertFinder);
        }
        
        try {
            token.init(properties, data, cryptoTokenId);
        } catch (NoSuchSlotException e) {
            final String msg = "Unable to access PKCS#11 slot for crypto token '"+tokenName+"' (" + cryptoTokenId + "). Perhaps the token was removed? " + e.getMessage();
            if (allowNonExistingSlot) {
                log.warn(msg);
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug(msg, e);
                }
                throw e;
            }
        } catch (Exception e) {
            log.error("Error initializing Crypto Token '"+tokenName+"' (" + cryptoTokenId + "). Classpath=" + classname, e);
        }
        token.setTokenName(tokenName);
        return token;
    }
    
    private static final CryptoToken createTokenFromClass(final String classpath) {
    	try {
    		Class<?> implClass = Class.forName(classpath);
    		Object obj = implClass.getDeclaredConstructor().newInstance();
    		return (CryptoToken) obj;
    	} catch (Throwable e) {
    		log.error("Error contructing Crypto Token (setting to null). Classpath="+classpath, e);
    		return null;
    	}
    }
}
