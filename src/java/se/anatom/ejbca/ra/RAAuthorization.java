package se.anatom.ejbca.ra;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.authorization.AvailableAccessRules;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;

/**
 * A class that looks up the which CA:s or end entity profiles the administrator is authorized to view.
 * 
 * @version $Id: RAAuthorization.java,v 1.1 2003-09-04 08:51:44 herrvendil Exp $
 */
public class RAAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of RAAuthorization. */
    public RAAuthorization(Admin admin, IRaAdminSessionLocal raadminsession, IAuthorizationSessionLocal authorizationsession) {
      this.admin=admin;
      this.raadminsession=raadminsession;
      this.authorizationsession=authorizationsession;
    }

    
    
    /**
     * Method that checks the administrators CA privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of administrators CA privileges that should be used in the where clause of SQL queries.
     */
    public String getCAAuthorizationString() {      
      if(authcastring==null){
        Iterator iter =  this.authorizationsession.getAuthorizedCAIds(admin).iterator();
         
        authcastring = "";
        
        while(iter.hasNext()){
          if(authcastring.equals(""))
            authcastring = " caid = " + ((Integer) iter.next()).toString();   
          else    
            authcastring = authcastring + " OR caid = " + ((Integer) iter.next()).toString(); 
        }
        
        if(!authcastring.equals(""))
          authcastring = "( " + authcastring + " )"; 
 
      }
      
      return authcastring;
    } 
    
    /**
     * Method that checks the administrators end entity profile privileges and returns a string that should be used in where clause of userdata SQL queries.
     *
     * @return a string of end entity profile privileges that should be used in the where clause of SQL queries.
     */
    public String getEndEntityProfileAuthorizationString(){
      if(authendentityprofilestring==null){
        Iterator iter =  this.authorizationsession.getAuthorizedEndEntityProfileIds(admin, AvailableAccessRules.VIEW_RIGHTS).iterator();
         
      
        while(iter.hasNext()){
          if(authendentityprofilestring == null)
            authendentityprofilestring = " endEntityprofileId = " + ((Integer) iter.next()).toString();   
          else    
            authendentityprofilestring = authendentityprofilestring + " OR endEntityprofileId = " + ((Integer) iter.next()).toString(); 
        }
        
        authendentityprofilestring = "( " + authendentityprofilestring + " )"; 
          
      }
        
      return authendentityprofilestring; 
    }
    
    
    public TreeMap getAuthorizedEndEntityProfileNames(){
      if(authprofilenames==null){
        authprofilenames = new TreeMap();  
        Iterator iter = raadminsession.getAuthorizedEndEntityProfileIds(admin).iterator();      
        HashMap idtonamemap = raadminsession.getEndEntityProfileIdToNameMap(admin);
        while(iter.hasNext()){
          Integer id = (Integer) iter.next();
          authprofilenames.put(idtonamemap.get(id),id);
        }
      }
      return authprofilenames;  
    }
    
    public void clear(){
      authcastring=null;
      authendentityprofilestring=null;
      authprofilenames = null;
    }
    
    // Private fields.
    private String authcastring = null;
    private String authendentityprofilestring = null;
    private TreeMap authprofilenames = null;
    private Admin admin;
    private IAuthorizationSessionLocal authorizationsession;
    private IRaAdminSessionLocal raadminsession;

}


