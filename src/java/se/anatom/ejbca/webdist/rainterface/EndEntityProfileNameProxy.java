/*
 * cProfileNameProxy.java
 *
 * Created on den 23 juli 2002, 17:49
 */

package se.anatom.ejbca.webdist.rainterface;
import java.util.HashMap;

import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;

/**
 * A class used to improve performance by proxying end entity profileid to profilename mappings by minimizing the number of needed lockups over rmi.
 * 
 * @author  TomSelleck
 */
public class EndEntityProfileNameProxy {
    
    /** Creates a new instance of ProfileNameProxy */
    public EndEntityProfileNameProxy(Admin administrator, IRaAdminSessionLocal raadminsession){
              // Get the RaAdminSession instance.
      this.raadminsession = raadminsession;  
      
      profilenamestore = new HashMap(); 
      this.administrator = administrator;  
    }
    
    /**
     * Method that first tries to find profilename in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param profileid the profile id number to look up.
     * @return the profilename or null if no profilename is relatied to the given id
     */
    public String getEndEntityProfileName(int profileid) {
      String returnval = null;  
      // Check if name is in hashmap
      returnval = (String) profilenamestore.get(new Integer(profileid));
      
      if(returnval==null){
        // Retreive profilename
        returnval = raadminsession.getEndEntityProfileName(administrator, profileid);
        if(returnval != null)
          profilenamestore.put(new Integer(profileid),returnval);
      }    
       
      return returnval;
    }
    
    // Private fields
    private HashMap profilenamestore;
    private IRaAdminSessionLocal raadminsession;
    private Admin   administrator;

}
