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
			    
    private static final long serialVersionUID = 1L;
    private ArrayList<AccessRule> currentruleset = new ArrayList<AccessRule>();
	
    /**
     * Tries to encode a advanced ruleset into basic ones. 
     * Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetDecoder(int currentrole, Collection<Integer> currentcas, Collection<Integer> currentendentityrules, Collection<Integer> currentendentityprofiles, Collection<Integer> currentotherrules){
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
    public Collection<AccessRule> getCurrentAdvancedRuleSet(){
    	return currentruleset;
    }

	private void addCARules(Collection<Integer> currentcas){
		boolean allcafound = false;
		
		Iterator<Integer> iter = currentcas.iterator();
		ArrayList<AccessRule> carules = new ArrayList<AccessRule>();
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
			
			if(next.equals(Integer.valueOf(BasicAccessRuleSet.CA_ALL))){
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
    
	private void addOtherRules(Collection<Integer> currentotherrules){
		Iterator<Integer> iter = currentotherrules.iterator();		
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
		
			if(next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_VIEWLOG))){
				currentruleset.add(new AccessRule(AccessRulesConstants.REGULAR_VIEWLOG, AccessRule.RULE_ACCEPT, true));
			}else
		    if(next.equals(Integer.valueOf(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS))){
		        currentruleset.add(new AccessRule(AccessRulesConstants.HARDTOKEN_ISSUEHARDTOKENS, AccessRule.RULE_ACCEPT, false));
			}
		}
	}
	
	private void addEndEntityRules(Collection<Integer> currentendentityprofiles, Collection<Integer> currentendentityrules){
		ArrayList<String> endentityrules = new ArrayList<String>();
				
		for(Integer next : currentendentityrules){		
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
	
	private void addEndEntityProfiles(Collection<Integer> currentendentityprofiles, Collection<String> endentityrules){
		boolean allexists = false;	   
	  	Iterator<Integer> iter =currentendentityprofiles.iterator(); 	
	  	ArrayList<AccessRule> profilerules = new ArrayList<AccessRule>();
	  	while(iter.hasNext() && !allexists){	  	  
	  	   Integer next = (Integer) iter.next();
	  	   if(next.intValue() == BasicAccessRuleSet.ENDENTITYPROFILE_ALL){	  	   	
	  	   	 allexists = true;
	  	   	 break;
	  	   }
	  	   Iterator<String> iter2 = endentityrules.iterator();	  	  
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
