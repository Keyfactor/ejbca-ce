package se.anatom.ejbca.authorization;

import java.io.Serializable;
import java.util.HashMap;

/**
 * A class used to improve performance by proxying administrator authorization request by minimizing the need of traversing
 * trough the authorization tree and rmi lookups. 
 *
 * @author  TomSelleck
 */
public class AuthorizationProxy implements Serializable {

    // Public Constants.
    
    /** Creates a new instance of AuthorizationProxy. */
    public AuthorizationProxy(AccessTree accesstree) {
              // Get the RaAdminSession instance.
       authstore = new HashMap();
       this.accesstree = accesstree;
    }


    /**
     * Method that first checks in hashmap if administrator already have been checked in accesstree.
     * If not it looks in the accesstree.
     */


    // Private Methods
    public boolean isAuthorized(AdminInformation admin, String resource){
      Boolean returnval = null;
      int adm = 0;
      
      if(admin.isSpecialUser()){
        adm = admin.getSpecialUser();
      }
      else
        adm = admin.getX509Certificate().getSerialNumber().hashCode();
      int tmp = adm ^ resource.hashCode();
        // Check if name is in hashmap
      returnval = (Boolean) authstore.get(new Integer(tmp));
      
      if(returnval != null) System.out.println("AuthorizationProxy :  result " + returnval);
      if(returnval==null){          
        // Get authorization from access tree
          returnval = new Boolean(accesstree.isAuthorized(admin, resource));
          authstore.put(new Integer(tmp),returnval);
          System.out.println("AuthorizationProxy :  returnval = null, result " + returnval.booleanValue());
        }

      return returnval.booleanValue();
    }

    /**
     * Method used to clear the proxy, should be called every time administrator priviledges have been
     * changed. 
     */
    public void clear(){
      this.authstore.clear();   
    }


    // Private fields.
    private HashMap                     authstore;
    private AccessTree                  accesstree;

}
