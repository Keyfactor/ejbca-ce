package se.anatom.ejbca.webdist.webconfiguration;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;

import se.anatom.ejbca.authorization.AccessRule;
import se.anatom.ejbca.authorization.AvailableAccessRules;

/**
 * A class used as a help class for displaying access rules
 *
 * @author  TomSelleck 
 */
public class AccessRulesView implements java.io.Serializable {

    
    /**
     * Creates an AccessRulesView and sorts the accessrules into their approriate
     * sets.
     */
    public AccessRulesView(Collection accessrules){
      this.rolebasedaccessrules = new ArrayList();
      this.regularaccessrules = new ArrayList();
      this.endentityprofileaccessrules = new ArrayList();
      this.caaccessrules = new ArrayList();
        
        
      Iterator iter = accessrules.iterator();
      while(iter.hasNext()){
        Object obj = iter.next();
        String accessrulestring = "";
        AccessRule accessrule = null;
        if( obj instanceof AccessRule ){
          accessrulestring = ((AccessRule) obj).getAccessRule();
          accessrule = (AccessRule) obj;
        }else{
          accessrulestring = (String) obj;
          accessrule = new AccessRule(accessrulestring, 0,  false);
        }  
        boolean regular = true;
        
        // Check if rule is a role based one
        for(int i=0; i< AvailableAccessRules.ROLEACCESSRULES.length; i++){
           if(accessrulestring.equals(AvailableAccessRules.ROLEACCESSRULES[i])){
             this.rolebasedaccessrules.add(accessrule);
             regular=false;
           }  
        }
        
        // Check if rule is end entity profile access rule
        if(accessrulestring.startsWith("/endentityprofilesrules")){
          this.endentityprofileaccessrules.add(accessrule);
          regular=false;
        }
        
        // Check if rule is CA access rule
        if(accessrulestring.startsWith(AvailableAccessRules.CAPREFIX)){
          this.caaccessrules.add(accessrule);
          regular=false;
        }        
        
        // Otherwise it's a regular accessrule.
        if(regular)
          this.regularaccessrules.add(accessrule);  
        
      } 
      
      Collections.sort(this.rolebasedaccessrules);
      Collections.sort(this.regularaccessrules);
      Collections.sort(this.endentityprofileaccessrules);
      Collections.sort(this.caaccessrules);
      
    }
    
   
    /**
     *  Method that returns all role based access rules, sorted.
     */
    public Collection getRoleBasedAccessRules(){
      return this.rolebasedaccessrules;   
    }

    /**
     *  Method that returns all regular access rules, sorted.
     */    
    public Collection getRegularAccessRules(){
      return this.regularaccessrules;   
    }
    
    /**
     *  Method that returns all end entity profile access rules, sorted.
     */    
    public Collection getEndEntityProfileAccessRules(){
      return this.endentityprofileaccessrules;   
    }

    /**
     *  Method that returns all CA access rules, sorted.
     */
    public Collection getCAAccessRules(){
      return this.caaccessrules;   
    }    
    
    // Private constants.  
    
    // Private methods.
    private ArrayList rolebasedaccessrules;
    private ArrayList regularaccessrules;
    private ArrayList endentityprofileaccessrules;
    private ArrayList caaccessrules;
}
