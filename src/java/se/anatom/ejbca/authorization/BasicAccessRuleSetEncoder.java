package se.anatom.ejbca.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;

import se.anatom.ejbca.authorization.AccessRule;
import se.anatom.ejbca.authorization.AvailableAccessRules;

/**
 * A class used as a help class for displaying and configuring basic access rules
 *
 * @author  herrvendil 
 * @version $Id: BasicAccessRuleSetEncoder.java,v 1.1 2004-02-11 10:43:15 herrvendil Exp $
 */
public class BasicAccessRuleSetEncoder implements java.io.Serializable {

	private boolean forceadvanced = true;
	private int currentrole = BasicAccessRuleSet.ROLE_RAADMINISTRATOR;
	private Collection availableroles = new ArrayList();
	private Collection currentcas = new ArrayList();
	private Collection availablecas = new ArrayList();
	private Collection currentendentityrules = new ArrayList();
	private Collection availableendentityrules = new ArrayList();
	private Collection currentendentityprofiles = new ArrayList();
	private Collection availableendentityprofiles = new ArrayList();
	private Collection currentotherrules = new ArrayList();
	private Collection availableotherrules = new ArrayList();
    
    /**
     * Tries to encode a advanced ruleset into basic ones. 
     * Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetEncoder(Collection currentaccessrules, Collection availableaccessrules){
        if(availableaccessrules.containsAll(currentaccessrules)){
    	     HashSet currentruleset = new HashSet(currentaccessrules);
    	     HashSet availableruleset = new HashSet(availableaccessrules);
        }
    }
    
        
    /**
     * Returns true if basic configuration of access rules isn't possible.
     */
    public boolean getForceAdvanced(){
    	return forceadvanced;
    }

    /**
     * Returns the current role of the administrator group.
     * One of the BasicRuleSet ROLE_constants
     * 
     */
    
    public int getCurrentRole(){
    	return currentrole;
    }

    /**
     * Returns a Collection of basic roles the administrator is authorized to configure.
     * @return a Collection of BasicRuleSet.ROLE_constants (Integer)
     * 
     */   
    public Collection getAvailableRoles(){
    	return availableroles;
    }    

    /**
     * @return a Collection of CAids the administratorgroup is authorized to or BasicAccessRuleSet.CA_ALL for all cas.
     */       
    public Collection getCurrentCAs(){
    	return currentcas;
    }

    /**
     * @return a Collection of available CAids or BasicAccessRuleSet.CA_ALL for all cas.
     */          
    public Collection getAvailableCAs(){
    	return availablecas;
    }

    /**
     * @return a Collection of EndEntityRules the administratorgroup is authorized to, BasicAccessRuleSet.ENDENTITY_ constants (Integer).
     */           
	public Collection getCurrentEndEntityRules(){
		return currentendentityrules;		
	}
	
	/**
	 * @return a Collection of available EndEntityRules,  BasicAccessRuleSet.ENDENTITY_ constants (Integer)
	 */ 	
	public Collection getAvailableEndEntityRules(){
		return availableendentityrules;		
	}
	
	/**
	 * @return a Collection of authorized EndEntityProfileIds or BasicAccessRuleSet.ENDENTITYPROFILE_ALL for all
	 */          
	public Collection getCurrentEndEntityProfiles(){
		return currentendentityprofiles;
	}

	/**
	 * @return a Collection of available EndEntityProfileIds or BasicAccessRuleSet.ENDENTITYPROFILE_ALL for all and entity profiles.
	 */ 		
	public Collection getAvailableEndEntityProfiles(){
	   return availableendentityprofiles;	
	}
	
	/**
	 * @return a Collection of auhtorized other rules. (Integer).
	 */          
	public Collection getCurrentOtherRules(){
		return currentotherrules;		
	}
	
	/**
	 * @return a Collection of available other rules (Integer).
	 */ 		
	public Collection getAvailableOtherRules(){
	   return availableotherrules;	
	}
    
	private void initAvailableRoles(HashSet availableruleset){
	   	// Check if administrator can be superadministrator
		
        // Check if administrator can be caadministrator
		
		// Check if administrator can be raadministrator
		
		// Check if administrator can be supervisor
		
		// Check if administrator can be hardtokenissuer
		
	}
	
	private void initCurrentRole(IAuthorizationSessionLocal authorizationsession, Collection currentaccessrules){
		// Check if administrator is superadministrator
		
		// Check if administrator is caadministrator
		
		// Check if administrator is raadministrator
		
		// Check if administrator is supervisor
		
		// Check if administrator is hardtokenissuer
		
	}
	
}
