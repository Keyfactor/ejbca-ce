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
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;

/**
 * A class used as a help class for displaying and configuring basic access rules
 *
 * @author  herrvendil 
 * @version $Id: BasicAccessRuleSetEncoder.java,v 1.1 2006-01-17 20:30:56 anatom Exp $
 */
public class BasicAccessRuleSetEncoder implements java.io.Serializable {

	private boolean forceadvanced = false;
		
	private int currentrole = BasicAccessRuleSet.ROLE_NONE;
	private Collection availableroles = new ArrayList();
	private HashSet currentcas = new HashSet();
	private HashSet availablecas = new HashSet();
	private HashSet currentendentityrules = new HashSet();
	private ArrayList availableendentityrules = new ArrayList();
	private HashSet currentendentityprofiles = new HashSet();
	private HashSet availableendentityprofiles = new HashSet();
	private HashSet currentotherrules = new HashSet();
	private ArrayList availableotherrules = new ArrayList();
    
    /**
     * Tries to encode a advanced ruleset into basic ones. 
     * Sets the forceadvanced flag if encoding isn't possible.
     */
    public BasicAccessRuleSetEncoder(Collection currentaccessrules, Collection availableaccessrules, boolean usehardtokens, boolean usekeyrecovery){
    	 HashSet aar = new HashSet();
    	 aar.addAll(availableaccessrules);
    	 Iterator iter = currentaccessrules.iterator();
    	 while(iter.hasNext()) aar.add(((AccessRule) iter.next()).getAccessRule());    	 
    	 initAvailableRoles(aar);    	 
    	 initAvailableRules(usehardtokens, usekeyrecovery, aar);    	 
    	 
    	 initCurrentRole(currentaccessrules);    	 
    	 initCurrentRules(currentaccessrules);

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
    public HashSet getCurrentCAs(){
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
	public HashSet getCurrentEndEntityRules(){
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
	public HashSet getCurrentEndEntityProfiles(){
		return currentendentityprofiles;
	}

	/**
	 * @return a Collection of av	ailable EndEntityProfileIds or BasicAccessRuleSet.ENDENTITYPROFILE_ALL for all and entity profiles.
	 */ 		
	public Collection getAvailableEndEntityProfiles(){
	   return availableendentityprofiles;	
	}
	
	/**
	 * @return a Collection of auhtorized other rules. (Integer).
	 */          
	public HashSet getCurrentOtherRules(){
		return currentotherrules;		
	}
	
	/**
	 * @return a Collection of available other rules (Integer).
	 */ 		
	public Collection getAvailableOtherRules(){
	   return availableotherrules;	
	}
    
	private void initAvailableRoles(HashSet availableruleset){		
		availableroles.add(new Integer(BasicAccessRuleSet.ROLE_NONE));
        availableroles.add(new Integer(BasicAccessRuleSet.ROLE_CAADMINISTRATOR));
        
        availableroles.add(new Integer(BasicAccessRuleSet.ROLE_RAADMINISTRATOR));        
        availableroles.add(new Integer(BasicAccessRuleSet.ROLE_SUPERVISOR));                
		// Check if administrator can create superadministrators
		if(availableruleset.contains(AvailableAccessRules.ROLE_SUPERADMINISTRATOR)){						
			availableroles.add(new Integer(BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR));
		}	

	}
	
	private void initCurrentRole(Collection currentaccessrules){		
		// Check if administrator is superadministrator
		
		if(currentaccessrules.size() >0){
          if(isSuperAdministrator(currentaccessrules)){
        
        	  this.currentrole = BasicAccessRuleSet.ROLE_SUPERADMINISTRATOR;
          }else
		    // Check if administrator is caadministrator
            if(isCAAdministrator(currentaccessrules)){          	    
          	    this.currentrole = BasicAccessRuleSet.ROLE_CAADMINISTRATOR;
            }else        
		    // Check if administrator is raadministrator
            if(isRAAdministrator(currentaccessrules)){          	  
          	  this.currentrole = BasicAccessRuleSet.ROLE_RAADMINISTRATOR;
            }else
		    // Check if administrator is supervisor
            if(isSupervisor(currentaccessrules)){          	   
          	    this.currentrole = BasicAccessRuleSet.ROLE_SUPERVISOR;          	  	 
            }else
          	    this.forceadvanced = true;
		}else{
			this.currentrole = BasicAccessRuleSet.ROLE_NONE;
		}	        
	}
		
	private boolean isSuperAdministrator(Collection currentaccessrules){
		
		boolean returnval = false;
		if(currentaccessrules.size() ==1){
			AccessRule ar = (AccessRule) currentaccessrules.iterator().next();
			if(ar.getAccessRule().equals(AvailableAccessRules.ROLE_SUPERADMINISTRATOR) && 
					                                   ar.getRule() == AccessRule.RULE_ACCEPT &&
													   !ar.isRecursive())
				returnval = true;
		}
		
		return returnval;
	}
	
	private boolean isCAAdministrator(Collection currentaccessrules){
	   boolean returnval = false;
	 	   	   	   
	   if(currentaccessrules.size() >= 7){
	     HashSet requiredacceptrecrules = new HashSet();
	     requiredacceptrecrules.add(AvailableAccessRules.REGULAR_CAFUNCTIONALTY);
	     requiredacceptrecrules.add(AvailableAccessRules.REGULAR_LOGFUNCTIONALITY);
	     requiredacceptrecrules.add(AvailableAccessRules.REGULAR_RAFUNCTIONALITY);
	     requiredacceptrecrules.add(AvailableAccessRules.REGULAR_SYSTEMFUNCTIONALITY);	     
	     requiredacceptrecrules.add(AvailableAccessRules.ENDENTITYPROFILEBASE);
	     HashSet requiredacceptnonrecrules = new HashSet();
	     requiredacceptnonrecrules.add(AvailableAccessRules.ROLE_ADMINISTRATOR);
	     requiredacceptnonrecrules.add(AvailableAccessRules.HARDTOKEN_EDITHARDTOKENISSUERS);
	     requiredacceptnonrecrules.add(AvailableAccessRules.HARDTOKEN_EDITHARDTOKENPROFILES);
	     
	     Iterator iter = currentaccessrules.iterator();
	     boolean illegal = false;
	     while(iter.hasNext()){
	     	AccessRule ar = (AccessRule) iter.next();
	     	if(!isAllowedCAAdministratorRule(ar))
	     	  if(ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive() && requiredacceptrecrules.contains(ar.getAccessRule()))
	     	  		requiredacceptrecrules.remove(ar.getAccessRule());
	     	  else		
	     	  	if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive() && requiredacceptnonrecrules.contains(ar.getAccessRule()))
	     	  		requiredacceptnonrecrules.remove(ar.getAccessRule());
	     	    else{
	     	    	illegal = true;
					break;
	     	    }		     	
	     }
	     if(!illegal && requiredacceptrecrules.size()==0 && requiredacceptnonrecrules.size() == 0)
	     	returnval = true;
	     
	   }
	   

	   
	   return returnval;
	}
		
	private boolean isAllowedCAAdministratorRule(AccessRule ar){
		boolean returnval = false;
		
		if(ar.getAccessRule().equals(AvailableAccessRules.CABASE) && ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive())
			returnval = true;

		if(ar.getAccessRule().startsWith(AvailableAccessRules.CAPREFIX) && ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive())
			returnval = true;		
	
		if(ar.getAccessRule().startsWith(AvailableAccessRules.HARDTOKEN_ISSUEHARDTOKENS) && ar.getRule() == AccessRule.RULE_ACCEPT)
			returnval = true;
		
		return returnval;
	}
	
	private boolean isRAAdministrator(Collection currentaccessrules){
		boolean returnval = false;
		
		if(currentaccessrules.size() >= 4){
			HashSet requiredaccepnonrecrules = new HashSet();
			requiredaccepnonrecrules.add(AvailableAccessRules.ROLE_ADMINISTRATOR);
			requiredaccepnonrecrules.add(AvailableAccessRules.REGULAR_CREATECERTIFICATE);
			requiredaccepnonrecrules.add(AvailableAccessRules.REGULAR_STORECERTIFICATE);
			requiredaccepnonrecrules.add(AvailableAccessRules.REGULAR_VIEWCERTIFICATE);
						
			Iterator iter = currentaccessrules.iterator();
			boolean illegal = false;
			while(iter.hasNext()){
				AccessRule ar = (AccessRule) iter.next();	     	
				if(!isAllowedRAAdministratorRule(ar))
						if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive() && requiredaccepnonrecrules.contains(ar.getAccessRule()))
							requiredaccepnonrecrules.remove(ar.getAccessRule());
						else{
							illegal = true;
							break;
						}	
			}
			if(!illegal && requiredaccepnonrecrules.size() == 0)
				returnval = true;	     	    	     
		}
		
		return returnval;
	}
	
	
	private boolean isAllowedRAAdministratorRule(AccessRule ar){
		boolean returnval = false;
								
		if(ar.getRule() == AccessRule.RULE_ACCEPT){
		  if(ar.getAccessRule().equals(AvailableAccessRules.HARDTOKEN_ISSUEHARDTOKENS))
			  returnval = true;
		  if(ar.isRecursive()){
		  	  if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWLOG)) 
		  	  	 returnval = true; 
		      if(ar.getAccessRule().equals(AvailableAccessRules.ENDENTITYPROFILEBASE) ||
		         ar.getAccessRule().equals(AvailableAccessRules.CABASE))   	
		      	   returnval = true;
		  }else{
		  	  if(ar.getAccessRule().startsWith(AvailableAccessRules.REGULAR_RAFUNCTIONALITY + "/")
		  	  	  && !ar.getAccessRule().equals(AvailableAccessRules.REGULAR_EDITENDENTITYPROFILES))
		  	  	  returnval = true;
		  	  if(ar.getAccessRule().startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX))
		  	  	returnval = true;
		  	  if(ar.getAccessRule().startsWith(AvailableAccessRules.CAPREFIX))
		  	  	returnval = true;		  	  
		  } 	
		}
		return returnval;
	}	
	
	private boolean isSupervisor(Collection currentaccessrules){
		boolean returnval = false;
		
		if(currentaccessrules.size() >= 2){
			HashSet requiredacceptrecrules = new HashSet();
			requiredacceptrecrules.add(AvailableAccessRules.REGULAR_VIEWLOG);
			HashSet requiredacceptnonrecrules = new HashSet();
			requiredacceptnonrecrules.add(AvailableAccessRules.ROLE_ADMINISTRATOR);
			requiredacceptnonrecrules.add(AvailableAccessRules.REGULAR_VIEWCERTIFICATE);			
			Iterator iter = currentaccessrules.iterator();
			boolean illegal = false;
			while(iter.hasNext()){
				AccessRule ar = (AccessRule) iter.next();	     	
				if(!isAllowedSupervisorRule(ar))
					if(ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive() && requiredacceptrecrules.contains(ar.getAccessRule()))
						requiredacceptrecrules.remove(ar.getAccessRule());
					else		
						if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive() && requiredacceptnonrecrules.contains(ar.getAccessRule()))
							requiredacceptnonrecrules.remove(ar.getAccessRule());
						else{
							illegal = true;
							break;
						}	
			}
			if(!illegal && requiredacceptrecrules.size() ==0 && requiredacceptnonrecrules.size() == 0)
				returnval = true;
			

		}
				
		return returnval;
	}
	
	
	private boolean isAllowedSupervisorRule(AccessRule ar){
		boolean returnval = false;

		if(ar.getRule() == AccessRule.RULE_ACCEPT){
			if(ar.isRecursive()){
					if(ar.getAccessRule().equals(AvailableAccessRules.ENDENTITYPROFILEBASE) ||
							ar.getAccessRule().equals(AvailableAccessRules.CABASE))   	
						returnval = true;
			}else{
				if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWENDENTITY) ||
				   ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWENDENTITYHISTORY) ||
				   ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWHARDTOKENS) )
					returnval = true;
				if(ar.getAccessRule().startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX))
					returnval = true;
				if(ar.getAccessRule().startsWith(AvailableAccessRules.CAPREFIX))
					returnval = true;		  	  
			}
		}
		return returnval;				
	}
			
	private void initAvailableRules(boolean usehardtokens, boolean usekeyrecovery, Collection availableaccessrules){
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEW));
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));
		if(usehardtokens)
		  availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_CREATE));
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_EDIT));
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_DELETE));
		availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_REVOKE));
		if(usekeyrecovery)
		  availableendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_KEYRECOVER));
		
		Iterator iter = availableaccessrules.iterator();
		while(iter.hasNext()){
			String nextrule = (String) iter.next();
			if(nextrule.equals(AvailableAccessRules.CABASE)){
				this.availablecas.add(new Integer(BasicAccessRuleSet.CA_ALL));
			}else
		    if(nextrule.startsWith(AvailableAccessRules.CAPREFIX)){
		    	this.availablecas.add(new Integer(nextrule.substring(AvailableAccessRules.CAPREFIX.length())));
		    }else
		    if(nextrule.equals(AvailableAccessRules.ENDENTITYPROFILEBASE)){
		    	this.availableendentityprofiles.add(new Integer(BasicAccessRuleSet.ENDENTITYPROFILE_ALL));	
		    }else
		    if(nextrule.startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)){			    	
		    	if(nextrule.lastIndexOf('/') <= AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())
		    	  this.availableendentityprofiles.add(new Integer(nextrule.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length())));
		    	else	
		    	  this.availableendentityprofiles.add(new Integer(nextrule.substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length(), nextrule.lastIndexOf('/'))));		
		    }		    		    		    						
		}
		
		
		this.availableotherrules.add(new Integer(BasicAccessRuleSet.OTHER_VIEWLOG));
		if(usehardtokens)
			this.availableotherrules.add(new Integer(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS));
		
	}
	
	private void initCurrentRules(Collection currentaccessrules){		
		Iterator iter = currentaccessrules.iterator();
		HashMap endentityrules = new HashMap();
		
		Integer general = new Integer(0);
		endentityrules.put(general, new Integer(0));
		
		
		while(iter.hasNext()){
			AccessRule ar = (AccessRule) iter.next();			
									
			if(ar.getAccessRule().startsWith(AvailableAccessRules.REGULAR_RAFUNCTIONALITY) &&
				ar.getAccessRule().length() > AvailableAccessRules.REGULAR_RAFUNCTIONALITY.length() &&
			   !ar.getAccessRule().equals(AvailableAccessRules.REGULAR_EDITENDENTITYPROFILES)){
				if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive()){
					if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWENDENTITY)){
						
						currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEW));
						endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEW));	
					}else
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWENDENTITYHISTORY)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEWHISTORY));
				    }else
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_CREATEENDENTITY)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_CREATE));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_CREATE));				    	
				    }else
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_DELETEENDENTITY)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_DELETE));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_DELETE));				    	
				    }else
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_EDITENDENTITY)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_EDIT));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_EDIT));				    	
				    }else
				     if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_REVOKEENDENTITY)){				     	
				     	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_REVOKE));							
				     	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_REVOKE));				     	
				    }else				    	
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWHARDTOKENS)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS));				    	
				    }else
				    if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_KEYRECOVERY)){				    	
				    	currentendentityrules.add(new Integer(BasicAccessRuleSet.ENDENTITY_KEYRECOVER));							
				    	endentityrules.put(general,  new Integer(((Integer) endentityrules.get(general)).intValue() + BasicAccessRuleSet.ENDENTITY_KEYRECOVER));				    	
				    }				    						
				}else{
				   this.forceadvanced = true;
				   break;
				}				
			}else{
				if(ar.getAccessRule().equals(AvailableAccessRules.ENDENTITYPROFILEBASE)){
				  if(ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive()){				  	
				       this.currentendentityprofiles.add(new Integer(BasicAccessRuleSet.ENDENTITYPROFILE_ALL));
				  }else{
				  	this.forceadvanced = true;
				  	break;				  	
				  }
				}else
				if(ar.getAccessRule().startsWith(AvailableAccessRules.ENDENTITYPROFILEPREFIX)){
				  if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive()){
                    Integer profileid = null; 
				  	if(ar.getAccessRule().lastIndexOf('/') > AvailableAccessRules.ENDENTITYPROFILEPREFIX.length()){
					  profileid = new Integer(ar.getAccessRule().substring(AvailableAccessRules.ENDENTITYPROFILEPREFIX.length(), ar.getAccessRule().lastIndexOf('/')));
				  	}else{
				  		this.forceadvanced = true;
				  		break;
				  	}
					int currentval = 0;
					if(endentityrules.get(profileid) != null)
						currentval = ((Integer) endentityrules.get(profileid)).intValue();
					
					if(ar.getAccessRule().endsWith(AvailableAccessRules.VIEW_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_VIEW;
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.HISTORY_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_VIEWHISTORY;	
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.HARDTOKEN_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_VIEWHARDTOKENS;								
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.CREATE_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_CREATE;				
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.DELETE_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_DELETE;				
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.EDIT_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_EDIT;
					}else
					if(ar.getAccessRule().endsWith(AvailableAccessRules.REVOKE_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_REVOKE;
					}else						
					if(ar.getAccessRule().endsWith(AvailableAccessRules.KEYRECOVERY_RIGHTS)){
						currentval += BasicAccessRuleSet.ENDENTITY_KEYRECOVER;
					}
					endentityrules.put(profileid, new Integer(currentval));					
				  }else{
				  	this.forceadvanced = true;
				  	break;
				  }
				}else{
                  if(ar.getAccessRule().equals(AvailableAccessRules.CABASE)){
                  	if(ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive()){                  	
                  	  this.currentcas.add(new Integer(BasicAccessRuleSet.CA_ALL));
                    }else{
                  	  this.forceadvanced = true;
                  	  break;
                    }                  
                  }else{
                   	 if(ar.getAccessRule().startsWith(AvailableAccessRules.CAPREFIX)){
                   	 	if(ar.getRule() == AccessRule.RULE_ACCEPT && !ar.isRecursive()){                  	
                           Integer caid = new Integer(ar.getAccessRule().substring(AvailableAccessRules.CAPREFIX.length()));
                           this.currentcas.add(caid);
                   	 	}else{
                   	 		this.forceadvanced = true;
                   	 		break;
                   	 	}                                     	 	
                  	 }else{
                  	 	  if(ar.getAccessRule().equals(AvailableAccessRules.REGULAR_VIEWLOG)){
                  	 	      if(ar.getRule() == AccessRule.RULE_ACCEPT && ar.isRecursive()){
                  	 	  	    this.currentotherrules.add( new Integer(BasicAccessRuleSet.OTHER_VIEWLOG));
                  	 	      }else{
                  	 	      	this.forceadvanced = true;
                  	 	      	break;                  	 	      	
                  	 	      }
                  	 	  }else
                  	 	  if(ar.getAccessRule().equals(AvailableAccessRules.HARDTOKEN_ISSUEHARDTOKENS)){
                  	 	  		if(ar.getRule() == AccessRule.RULE_ACCEPT){
                  	 	  			this.currentotherrules.add( new Integer(BasicAccessRuleSet.OTHER_ISSUEHARDTOKENS));
                  	 	  		}else{
                  	 	  			this.forceadvanced = true;
                  	 	  			break;                  	 	      	                  	 	  			
                  	 	  		}
                  	 	  }
                  	 }
                  }
				}
			}			
		}
		
						
		
		int endentityruleval = ((Integer) endentityrules.get(general)).intValue();	
		
		iter = endentityrules.keySet().iterator();
		while(iter.hasNext()){
			Integer next = (Integer) iter.next();
			if(!next.equals(general)){
				if(((Integer) endentityrules.get(next)).intValue() == endentityruleval ){
					this.currentendentityprofiles.add(next);
				}else
					this.forceadvanced = true;
			}			
		}

	}
	 	
}
