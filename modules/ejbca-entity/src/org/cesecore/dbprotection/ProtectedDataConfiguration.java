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

package org.cesecore.dbprotection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.commons.configuration.Configuration;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.config.ConfigurationHolder;
import org.cesecore.keys.token.CryptoToken;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenFactory;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.util.Base64;

/**
 * This file handles configuration from conf/databaseprotection.properties. It is a Singleton.
 * 
 * Properties in file:
 * <pre>
 * databaseprotection.erroronverifyfail = true
 * databaseprotection.keyid = (keyid) 
 * databaseprotection.keyid.0 = (keyid)
 * databaseprotection.keylabel.0 (key label to use)
 * databaseprotection.classname.0 = (classname, ex org.cesecore.keys.token.SoftCryptoToken)
 * databaseprotection.properties.0 = (serialized token properties)
 * databaseprotection.data.0 = (base64 encoded token data)
 * databaseprotection.tokenpin.0 = userpin1 (activation code for crypto token)
 * databaseprotection.version.0 = 2 (1 = HMACSHA256, 2 = SHA256WithRSA, keys pointed by label must match type)
 * </pre>
 * Multiple crypto tokens can be repeated by using xx.1.(keyid) etc, where keyid is an integer, defined by you.
 * this makes it possible to start using a new crypto token with new keys, while still being able to verify older protected rows.
 * 
 * Based on CESeCore version:
 *      ProtectedDataConfiguration.java 897 2011-06-20 11:17:25Z johane
 * 
 * @version $Id$
 */
public final class ProtectedDataConfiguration {

	private static final Logger log = Logger.getLogger(ProtectedDataConfiguration.class);
	
	/** This is a singleton so it's not allowed to create an instance explicitly */ 
	private ProtectedDataConfiguration() {}

    /**
     * Map for keyid's and CryptoTokens
     */
    private final Map<Integer, CryptoToken> cryptoTokens = new HashMap<Integer, CryptoToken>();
    
    /**
     * Map of keyids and key labels, identifying which key label in a specific crypto token is used for a protection keyid
     */
    private final Map<Integer, String> keyLabels = new HashMap<Integer, String>();

    /**
     * Map of keyids and protect version, identifying which protect verison (hmac/dig sig etc) in a specific crypto token is used for a protection keyid
     */
    private final Map<Integer, Integer> protectVersions = new HashMap<Integer, Integer>();

    private Integer defaultkeyId;
    
    private static ProtectedDataConfiguration config = null;
    
    public static synchronized ProtectedDataConfiguration instance() {
    	if (config == null) {
    		config = new ProtectedDataConfiguration();
    		config.fillKeyIdsAndCryptoTokens();
    	}
    	return config;
    }

    public static void reload() {
    	config = null;
    	ProtectedDataConfiguration.instance();
    }
    public CryptoToken getCryptoToken(final int keyid) {
    	return cryptoTokens.get(Integer.valueOf(keyid));
	}

    public String getKeyLabel(final int keyid) {
    	return keyLabels.get(Integer.valueOf(keyid));
	}

    public Integer getProtectVersion(final int keyid) {
    	Integer ret = protectVersions.get(Integer.valueOf(keyid));
    	if (ret == null) {
    		ret = 2; // Default value
    	}
    	return ret;
	}

    public Integer getKeyId(final String tableName) {
		// First check if we have explicit configuration for this entity
    	final String configString = "databaseprotection.keyid." + tableName;
		final String keyId = ConfigurationHolder.getString(configString);
		try {
			if (keyId != null) {
				return Integer.valueOf(keyId);
			}
		} catch (NumberFormatException e) {
			log.error(configString + " is misconfigured. Not decimal a number. Default will be used.");
		}
		// Otherwise use the global or default
		return defaultkeyId;
	}

    public static boolean errorOnVerifyFail() {
		return !Boolean.FALSE.toString().equalsIgnoreCase(ConfigurationHolder.getString("databaseprotection.erroronverifyfail"));
    }

	/** If database integrity protection should be used or not. */
	public static boolean useDatabaseIntegrityProtection(final String tableName) {
		// First check if we have explicit configuration for this entity
		final String enableProtect = ConfigurationHolder.getString("databaseprotection.enablesign." + tableName);
		if (enableProtect != null) {
			return Boolean.TRUE.toString().equalsIgnoreCase(enableProtect);
		}
		// Otherwise use the global or default
		return Boolean.TRUE.toString().equalsIgnoreCase(ConfigurationHolder.getString("databaseprotection.enablesign"));
	}

	/** If database integrity verification should be used or not. */
	public static boolean useDatabaseIntegrityVerification(final String tableName) {
		// First check if we have explicit configuration for this entity
		final String enableVerify = ConfigurationHolder.getString("databaseprotection.enableverify." + tableName);
		if (enableVerify != null) {
			return Boolean.TRUE.toString().equalsIgnoreCase(enableVerify);
		}
		// Otherwise use the global or default
		return Boolean.TRUE.toString().equalsIgnoreCase(ConfigurationHolder.getString("databaseprotection.enableverify"));
	}

	/**
     * Fill the maps with crypto tokens and key labels from the configuration file
     */
	private void fillKeyIdsAndCryptoTokens() {
    	final Configuration conf = ConfigurationHolder.instance();
    	final String keyidstr = "databaseprotection.keyid.";
    	final String labelstr = "databaseprotection.keylabel.";
    	final String classtr = "databaseprotection.classname.";
    	final String propstr = "databaseprotection.properties.";
    	final String datastr = "databaseprotection.data.";
    	final String pinstr = "databaseprotection.tokenpin.";
    	final String versionstr = "databaseprotection.version.";
    	for (int i = 0; i < 255; i++) {
    		final String keyid = conf.getString(keyidstr+i);
    		if (keyid != null) {
    			// Get label, must exist
    			String label = conf.getString(labelstr+i);
    			if (label != null) {
    				// A null value in the properties file means that we should not use this value, so set it to null for real
    				if (label.equalsIgnoreCase("null")) {
    					label = null;
        				log.info("Found keyid "+keyid+", but label defined as 'null'. Not adding to list of crypto tokens.");
    				} else {
    					// Get version string, there is a default
    					final String version = conf.getString(versionstr+i);
    					if (StringUtils.isNotEmpty(version)) {
    						protectVersions.put(Integer.parseInt(keyid), Integer.parseInt(version));
    					}
    					// Get classname, must exist
    					final String classname = conf.getString(classtr+i);
    					if (StringUtils.isNotEmpty(classname)) {
        					// Get properties and data not required
    						// Properties (string with comma in it) are returned as an ArrayList so we can not use: final String str = conf.getString(propstr+i);
    						Object o = conf.getProperty(propstr+i);
    						String str = "";
    						if (o instanceof String) {
								str = (String)o;								
							} else if (o != null) {
								@SuppressWarnings("unchecked")
	    						final ArrayList<String> list = (ArrayList<String>)o;
	    						// We have to do a bit of magic in order to make the properties into something that 
	    						// Properties.load will swallow, it is a bit stupid.
	    						for (String s : list) {
	    							if (str.length() > 0) {
	    								str += "\n";
	    							}
	    							str += s;
								}
							}
        					final Properties properties = new Properties();
        					try {
        						if (StringUtils.isNotEmpty(str)) {
        							// Remove any curly braces from the input, otherwise Properties.load does not do what we want
        							str = StringUtils.remove(str, '{');
        							str = StringUtils.remove(str, '}');
        							// If the input string contains \ (backslash on windows) we must convert it to \\
        							// Otherwise properties.load will parse it as an escaped character, and that is not good
        							str = StringUtils.replace(str, "\\", "\\\\");
    								properties.load(new ByteArrayInputStream(str.getBytes()));        							
        						}
	        					final String data = conf.getString(datastr+i);
	        					byte[] keydata = null;
	        					if (StringUtils.isNotEmpty(data)) {
		        					// Data is base64 encoded byte[] so decode it
		        					keydata = Base64.decode(data.getBytes());	        						
	        					}
	        					final CryptoToken token = CryptoTokenFactory.createCryptoToken(classname, properties, keydata, Integer.valueOf(keyid));
	        					// We must activate the token as well (if not using a default pwd of course, in which case we assume the tokenpin property is not set)
	        					final String pin = conf.getString(pinstr+i);
	        					try {
	        						if (StringUtils.isNotEmpty(pin)) {
	        							token.activate(pin.toCharArray());
	        						}
	        						cryptoTokens.put(Integer.parseInt(keyid), new CachedCryptoToken(token));
	        						keyLabels.put(Integer.parseInt(keyid), label);
	        					} catch (CryptoTokenAuthenticationFailedException e) {
		    	    				log.error("Found keyid "+keyid+", but activation of crypto token fails. Not adding to list of crypto tokens.", e);    						
	        					} catch (CryptoTokenOfflineException e) {
		    	    				log.error("Found keyid "+keyid+", but activation of crypto token fails. Not adding to list of crypto tokens.", e);    						
								}
							} catch (IOException e) {
	    	    				log.error("Found keyid "+keyid+", but properties fails to load. Not adding to list of crypto tokens.", e);    						
							}
    					} else {
    	    				log.error("Found keyid "+keyid+", but no classname defined. Not adding to list of crypto tokens.");    						
    					}
    				}
    			} else {
    				log.error("Found keyid "+keyid+", but no label defined. Not adding to list of crypto tokens.");
    			}
    		} else {
    			// No keyid with that number = no more keyids so break,
    			log.debug("Read "+i+" crypto tokens for protected data.");
    			break;
    		}

    		// After reading this, get the default key label
        	final String defaultstr = "databaseprotection.keyid";
			final String defkeyid = conf.getString(defaultstr);
			if (StringUtils.isEmpty(defkeyid)) {
				log.error("No default key id, will not be able to use database protection.");				
			}
			defaultkeyId = Integer.valueOf(defkeyid);

    	}
    }

}
