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
package org.ejbca.core.model;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import javax.ejb.EJBException;

import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/**
 * Class managing internal localization of texts such as notification messages
 * and log comments.
 * 
 * If fetched the resource files from the src/intlocalization directory and
 * is included in the file ejbca-ejb.jar
 *  
 * @author Philip Vendil 2006 sep 24
 *
 * @version $Id: InternalResources.java,v 1.2 2006-10-23 16:25:10 anatom Exp $
 */
public class InternalResources {
	
	protected static InternalResources instance = null;
	
	protected static Properties primaryResource = new Properties();
	protected static Properties secondaryResource = new Properties();
	
	private static final String RESOURCE_LOCATION =  "/intresources/intresources.";
	
	/**
	 * Method used to setup the Internal Resource management.  
	 * 
	 * @param globalConfiguration used to retrieve the internal language
	 * of the application, configured in the System Configuration.
	 */
	protected InternalResources(boolean test) {		
		String primaryLanguage = GlobalConfiguration.PREFEREDINTERNALRESOURCES.toLowerCase();
		String secondaryLanguage = GlobalConfiguration.SECONDARYINTERNALRESOURCES.toLowerCase();
		// The test flag is defined when called from test code (junit)		
	    InputStream primaryStream = null;
	    InputStream secondaryStream = null;
	    if (test) {
			primaryLanguage = "se";
			secondaryLanguage = "en";
		    try {
				primaryStream = new FileInputStream("src/intresources/intresources." + primaryLanguage + ".properties");
			    secondaryStream = new FileInputStream("src/intresources/intresources." + secondaryLanguage + ".properties");	    	
			} catch (FileNotFoundException e) {}
	    } else {
			primaryStream = InternalResources.class.getResourceAsStream(RESOURCE_LOCATION + primaryLanguage + ".properties");
			secondaryStream = InternalResources.class.getResourceAsStream(RESOURCE_LOCATION + secondaryLanguage + ".properties");	    	
	    }
		
		try {
			primaryResource.load(primaryStream);
			secondaryResource.load(secondaryStream);
		} catch (IOException e) {			
			throw new EJBException("Error reading internal resourcefile", e);
		}
	}
	
	/**
	 * Metod that returs a instance of the InternalResources
	 * might be null if load() haven't been called before this method.
	 */
	public static InternalResources getInstance(){
		if(instance == null){
			instance = new InternalResources(false);
		}
		return instance;
	}
	
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "No text available" is returned.
	 * 
	 */
    public String getLocalizedMessage(String key){
    	String retval = primaryResource.getProperty(key);
    	if(retval == null){
    		retval = secondaryResource.getProperty(key);
    	}
    	if(retval == null){
    		retval = "No text available";
    	}
    	return retval.trim();
    }
	

	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {0}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0){
    	Object[] params = {param0};
    	return getLocalizedMessage(key,params, 1);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {0}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1){
    	Object[] params = {param0,param1};
    	return getLocalizedMessage(key,params, 2);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0,Object param1, Object param2){
    	Object[] params = {param0,param1,param2};
    	return getLocalizedMessage(key,params, 3);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3){
    	Object[] params = {param0,param1,param2,param3};
    	return getLocalizedMessage(key,params, 4);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4){
    	Object[] params = {param0,param1,param2,param3,param4};
    	return getLocalizedMessage(key,params, 5);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5){
    	Object[] params = {param0,param1,param2,param3,param4,param5};
    	return getLocalizedMessage(key,params, 6);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6){
    	Object[] params = {param0,param1,param2,param3,param4,param5,param6};
    	return getLocalizedMessage(key,params, 7);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6, Object param7){
    	Object[] params = {param0,param1,param2,param3,param4,param5,param6,param7};
    	return getLocalizedMessage(key,params, 8);
    }   
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {1}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6, Object param7, Object param8){
    	Object[] params = {param0,param1,param2,param3,param4,param5,param6,param7,param8};
    	return getLocalizedMessage(key,params, 9);
    }
    
	/**
	 * Method returning the localized message for the given resource key.
	 * 
	 * It first looks up in the primary language then in the secondary
	 * If not found in any of the resource file "no text" is returned.
	 * 
	 * @param key is the key searched for in the resource files
	 * @param paramX indicaties the parameter that will be replaced by {X} in
	 * the language resource, a maximum of 10 parameters can be given.
	 * 
	 * Ex Calling the method with key = TEST and param0 set to "hi"
	 * and the resource file have "TEST = messages is {0}" will
	 * result in the string "message is hi".
	 * 
	 */
    public String getLocalizedMessage(String key, Object param0, Object param1, Object param2, Object param3, Object param4, Object param5, Object param6, Object param7, Object param8, Object param9){
    	Object[] params = {param0,param1,param2,param3,param4,param5,param6,param7,param8,param9};
    	return getLocalizedMessage(key,params, 10);
    }
    
    private String getLocalizedMessage(String key, Object[] params, int numOfParams){
    	String localizedString = getLocalizedMessage(key);
    	for(int i=0;i<numOfParams;i++){
    		localizedString = localizedString.replaceAll("\\{" + i + "\\}", params[i].toString());
    	}
    	
    	return localizedString;
    }
}
