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
 
package org.ejbca.core.model.authorization;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

/**
 * A class used as a help class for displaying and configuring basic access rules
 *
 * @author  herrvendil 
 * @version $Id$
 */
public class BasicAccessRuleSetDecoder implements java.io.Serializable {
			    
	private ArrayList currentruleset = new ArrayList();
	
    /**
     * Tries to encode a advanced ruleset into basic ones. 
     * Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetDecoder(int currentrole, Collection currentcas, Collection currentendentityrules, Collection currentendentityprofiles, Collection currentotherrules){
    	if(currentrole != BasicAccessRuleSet.ROLE_NONE){
          if(currentrole == BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR){
         	currentruleset.add(new AccessRule(AccessRulesConstants.ROLE_SUPERADMINISTRATOR, AccessRule.RULE_ACCEPT, false));        	
          }else{
            addCARules(currentcas); 	
            addOtherRules(currentotherrules);
            if(currentrole == BasicAccessRuleSet.ROLE_CAADMINISTRATOR){
          	  currentruleset.add(new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
          	
          	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_CAFUNCTIONALTY, AccessRule.RULE_ACCEPT, true));
          	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_LOGFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
          	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_RAFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
          	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_SYSTEMFUNCTIONALITY, AccessRule.RULE_ACCEPT, true));
          	  currentruleset.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT, true));
          	
          	  currentruleset.add(new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENISSUERS, AccessRule.RULE_ACCEPT, false));
          	  currentruleset.add(new AccessRule(AccessRulesConstants.HARDTOKEN_EDITHARDTOKENPROFILES, AccessRule.RULE_ACCEPT, false));
          	          	          	
            }else{
          	   addEndEntityRules(currentendentityprofiles, currentendentityrules);           	 
			   if(currentrole == BasicAccessRuleSet.ROLE_RAADMINISTRATOR){
			 	  currentruleset.add(new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
			 	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_CREATECERTIFICATE, AccessRule.RULE_ACCEPT, false));
			 	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_STORECERTIFICATE, AccessRule.RULE_ACCEPT, false));
			 	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRule.RULE_ACCEPT, false));			 	
			   }
          	   if(currentrole == BasicAccessRuleSet.ROLE_SUPERVISOR){
          	 	  currentruleset.add(new AccessRule(AccessRulesConstants.ROLE_ADMINISTRATOR, AccessRule.RULE_ACCEPT, false));
          	 	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWLOG, AccessRule.RULE_ACCEPT, true));
          	 	  currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWCERTIFICATE, AccessRule.RULE_ACCEPT, false));
          	   }
            }
          }
       }  
    }
    
        

    /**
     * Returns the current advanced rule set.
     * 
     * @return a Collection of AccessRule
     */    
    public Collection getCurrentAdvancedRuleSet(){
    	return currentruleset;
    }

	private void addCARules(Collection currentcas){
		boolean allcafound = false;
		
		Iterator iter = currentcas.iterator();
		ArrayList carules = new ArrayList();
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
			
			if(next.equals(new Integer(BasicAccessRuleSet.CA_ALL))){
				allcafound= true;
				break;
			}
			carules.add(new AccessRule(AccessRulesConstants.CAPREFIX + next.toString(), AccessRule.RULE_ACCEPT, false));			
		}
		
		if(allcafound){
			carules.clear();
			carules.add(new AccessRule(AccessRulesConstants.CABASE, AccessRule.RULE_ACCEPT, true));
		}
		
		this.currentruleset.addAll(carules);
		
	}
    
	private void addOtherRules(Collection currentotherrules){
		Iterator iter = currentotherrules.iterator();		
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
		
			if(next.equals(new Integer(BasicAccessRuleSet.OTHER_VIEWLOG))){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWLOG, AccessRule.RULE_ACCEPT, true));
			}else
		    if(next.equals(new Integer(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS))){
		        currentruleset.add(new AccessRule(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRule.RULE_ACCEPT, false));
			}
		}
	}
	
	private void addEndEntityRules(Collection currentendentityprofiles, Collection currentendentityrules){
		ArrayList endentityrules = new ArrayList();
				
		Iterator iter = currentendentityrules.iterator();
		while(iter.hasNext()){
			int next = ((Integer) iter.next()).intValue();
			
			if(next == BasicAccessRuleSet.ENDENTITY_VIEW){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.VIEW_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_VIEWHISTORY){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWENDENTITYHISTORY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.HISTORY_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWHARDTOKENS, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.HARDTOKEN_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_CREATE){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_CREATEENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.CREATE_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_DELETE){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_DELETEENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.DELETE_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_EDIT){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_EDITENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.EDIT_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_REVOKE){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_REVOKEENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.REVOKE_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_KEYRECOVER){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_KEYRECOVERY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.KEYRECOVERY_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_APPROVE){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_APPROVEENDENTITY, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.APPROVAL_RIGHTS);
			}else
			if(next == BasicAccessRuleSet.ENDENTITY_VIEWPUK){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWPUKS, AccessRule.RULE_ACCEPT, false));
				endentityrules.add(AccessRulesConstants.HARDTOKEN_PUKDATA_RIGHTS);
			}
		}
		
		addEndEntityProfiles(currentendentityprofiles, endentityrules);
	}
	
	private void addEndEntityProfiles(Collection currentendentityprofiles, Collection endentityrules){
		boolean allexists = false;	   
	  	Iterator iter =currentendentityprofiles.iterator();
	  	
	  	
	  	ArrayList profilerules = new ArrayList();
	  	while(iter.hasNext() && !allexists){	  	  
	  	   Integer next = (Integer) iter.next();
	  	   if(next.intValue() == BasicAccessRuleSet.ENDENTITYPROFILE_ALL){	  	   	
	  	   	 allexists = true;
	  	   	 break;
	  	   }
	  	   Iterator iter2 = endentityrules.iterator();	  	  
	  	   String profilerule = AccessRulesConstants.ENDENTITYPROFILEPREFIX + next.toString();
	  	   while(iter2.hasNext()){
	  	   	 String nextrule = (String) iter2.next(); 
	  	   	 profilerules.add(new AccessRule(profilerule + nextrule, AccessRule.RULE_ACCEPT, false));
	  	   }	  			  		
	  	}		
	  	
	  	if(allexists){
	  		profilerules.clear();
	  		profilerules.add(new AccessRule(AccessRulesConstants.ENDENTITYPROFILEBASE, AccessRule.RULE_ACCEPT,true));
	  	}
	  	currentruleset.addAll(profilerules);
	}
	
}
