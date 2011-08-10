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
 
/*
 * AccessRule.java
 *
 * Created on den 16 mars 2002, 13:25
 */

package org.ejbca.core.model.authorization;

import java.io.Serializable;

import org.cesecore.authorization.access.AccessTreeNode;


/**
 * A class representing an accessrule. 
 * A class representing an accessrule in the Ejbca package. Sets rules to resources and tell if it
 * also should apply for subresources.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class AccessRule implements Serializable, Comparable<Object> {

	private static final long serialVersionUID = 3554408014578253352L;
	
	// Public rule constants. 
    public static final int RULE_NOTUSED = 0;
    public static final int RULE_ACCEPT = 1;
    public static final int RULE_DECLINE = 2;
    
    public static final String[] RULE_TEXTS = {"UNUSED", "ACCEPT", "DECLINE"};
	
    /** Creates a new instance of AccessRule */
    public AccessRule(String accessrule, int rule, boolean recursive ) {
        this.accessrule=accessrule.trim();
        this.rule=rule;
        this.recursive=recursive;
        
        setState();
    }
    
    public int getRule() {
      return rule;   
    }
    
    public boolean isRecursive() {
      return recursive;  
    }
    
    public String getAccessRule() {
      return accessrule;
    }
    
    public void setRule(int rule) {
      this.rule=rule;
      setState();
    }
    
    public void setRecursive(boolean recursive) {
      this.recursive=recursive;
      setState();
    }
    
    public void setAccessRule(String accessrule) {
        this.accessrule=accessrule.trim();
    }
    
    /** Method used by the access tree to speed things up. */
    public int getRuleState(){
      return state;   
    }
    
    public int compareTo(Object obj) {
      return accessrule.compareTo(((AccessRule)obj).getAccessRule());   
    }
    
    // Private methods.
    private void setState(){  
       if(recursive){
         switch(rule){
             case RULE_ACCEPT:
                 state = AccessTreeNode.STATE_ACCEPT_RECURSIVE;
                 break;
             case RULE_DECLINE:
                 state = AccessTreeNode.STATE_DECLINE_RECURSIVE;
                 break;
             default:
         }
       }
       else{
         switch(rule){
             case RULE_ACCEPT:
                 state = AccessTreeNode.STATE_ACCEPT;
                 break;
             case RULE_DECLINE:
                 state = AccessTreeNode.STATE_DECLINE;
                 break;
             default:
         }
       }
    }
      
    // Private fields.
    private boolean recursive;
    private int rule;
    private String accessrule;
    private int state; // A more efficent way of reprecenting rule and recusive.
}
