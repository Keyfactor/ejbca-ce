/*
 * AccessRule.java
 *
 * Created on den 16 mars 2002, 13:25
 */

package se.anatom.ejbca.ra.authorization;

import java.io.Serializable;
/**
 * A class representing an accessrule in the Ejbca package. Sets rules to resources and tell if it also
 * should apply for subresources.
 *
 * @author  Philip Vendil
 */
public class AccessRule implements Serializable, Comparable {
    // Public rule constants. 
    public static final int RULE_ACCEPT = 1;
    public static final int RULE_DECLINE = 2;
    
    /** Creates a new instance of AccessRule */
    public AccessRule(String resource, int rule, boolean recursive ) {
        this.resource=resource.trim();
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
    
    public String getResource() {
      return resource;
    }
    
    public void setRule(int rule) {
      this.rule=rule;
      setState();
    }
    
    public void setRecursive(boolean recursive) {
      this.recursive=recursive;
      setState();
    }
    
    public void setResource(String resource) {
        this.resource=resource.trim();
    }
    
    /** Method used by the access tree to speed things up. */
    public int getRuleState(){
      return state;   
    }
    
    public int compareTo(Object obj) {
      return resource.compareTo(((AccessRule)obj).getResource());   
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
    private String resource;
    private int state; // A more efficent way of reprecenting rule and recusive.
}
