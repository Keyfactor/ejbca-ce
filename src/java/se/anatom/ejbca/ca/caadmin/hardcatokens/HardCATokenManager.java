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

package se.anatom.ejbca.ca.caadmin.hardcatokens;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;

import se.anatom.ejbca.ca.caadmin.AvailableHardCAToken;

/**
 * Class managing available Hard CA Tokens. Each HardCaToken plug-in should register itself by using the method register.
 * 
 */
public class HardCATokenManager {
	
    /** Log4j instance for Base */
    private static transient Logger log = Logger.getLogger(HardCATokenManager.class);

    private static ArrayList availablehardcatokens = new ArrayList();

    private static boolean initialized = init(); 
    

    /**
     * Method used to register all plug-in classes to the manager.
     * All new plug-ins should add a loadClass call with it's classpath to this method.
     * 
     * @return true when finished initializing.
     */
	private static boolean init(){
        loadClass("se.anatom.ejbca.ca.caadmin.hardcatokens.StaticRegistering");
        loadClass("se.anatom.ejbca.ca.caadmin.hardcatokens.DummyHardCAToken");
        loadClass("se.anatom.ejbca.ca.caadmin.hardcatokens.HardCATokenSample");
    	return true;
    }

    
	
	/**
	 * Method loading a class in order to register itself to the manager.
	 * Should be used from the init() method only.
	 * 
	 * @param classpath 
	 */
    private static void loadClass(String classpath){
    	try {    		
			HardCATokenManager.class.getClassLoader().loadClass(classpath).newInstance();		
		} catch (ClassNotFoundException e) {
		    log.info("Class not found: "+classpath); // Do Nothing, just log
		} catch (InstantiationException e) {
		    log.error("InstantiationException: "+classpath); // Do Nothing, just log
		} catch (IllegalAccessException e) {
		    log.error("IllegalAccessException: "+classpath); // Do Nothing, just log
		}    
    }
        
    
	/**
	 * Method registering a HardCAToken plug-in as available to the system.
	 * 
	 * @param classpath the classpath of the plug-in
	 * @param name the general name used in adminweb-gui.
	 * @param translateable indicates if the name should be translated in adminweb-gui
	 * @param use indicates it this plug-in should be used.
	 * 
	 * @return true if registration went successful.
	 */
	public static boolean register(String classpath, String name, boolean translateable, boolean use) {
		boolean retval = false;		
		try {             
		   // Check that class exists	
		   log.debug("HardCATokenManager registering " + classpath);	
			
		   Class.forName(classpath).getName();	
			
		   availablehardcatokens.add(new AvailableHardCAToken(classpath, name, translateable, use));
			
		   retval = true;
           log.debug("Registered " + classpath + "Successfully.");
		} catch (ClassNotFoundException e) {
	       log.error("Error registering " + classpath + " couldn't find classpath");
		}			
		return retval;
	}
	
	/**
	 * Method returning to the system available HardCATokens
	 * 
	 * @return a Collection (AvailableHardCAToken) of registrered plug-ins.
	 */
	
	public static Collection getAvailableHardCATokens(){
	   return availablehardcatokens;	
	}

	/**
	 * Method returning to the available hardcatoken with given classpath
	 * .
	 * 
	 * @return the corresponding AvailableHardCAToken or null of classpath couldn't be found
	 */
	
	public static AvailableHardCAToken getAvailableHardCAToken(String classpath){
		AvailableHardCAToken retval = null;
        Iterator iter = availablehardcatokens.iterator();
        while(iter.hasNext()){
        	AvailableHardCAToken next = (AvailableHardCAToken) iter.next();
        	if(next.getClassPath().equals(classpath)){
        	  retval = next;
        	  break;
        	}  
        }
		return retval;	
	}
	
}
