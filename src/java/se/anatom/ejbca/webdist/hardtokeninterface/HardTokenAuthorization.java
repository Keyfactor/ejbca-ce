package se.anatom.ejbca.webdist.hardtokeninterface;

import java.io.Serializable;
import java.util.HashSet;
import java.util.Iterator;
import java.util.TreeMap;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.hardtoken.HardTokenIssuerData;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.log.Admin;

/**
 * A class that looks up the which Hard Token Issuers the administrator is authorized to view and edit
 * 
 * @version $Id: HardTokenAuthorization.java,v 1.1 2003-10-03 10:07:00 herrvendil Exp $
 */
public class HardTokenAuthorization implements Serializable {
    
  
    
    /** Creates a new instance of CAAuthorization. */
    public HardTokenAuthorization(Admin admin,  
                           IHardTokenSessionLocal hardtokensession, 
                           IAuthorizationSessionLocal authorizationsession) {
      this.admin=admin;
      this.hardtokensession=hardtokensession;            
      this.authorizationsession=authorizationsession;
    }

    /**
     * Method returning a TreeMap containing Hard Token Alias -> Hard Token Issuer Data
     * the administrator is authorized to view and edit
     * @return A TreeMap Hard Token Alias (String) -> HardTokenIssuerData
     */    
    public TreeMap getHardTokenIssuers(){  
      if(hardtokenissuers==null){            
		hardtokenissuers = new TreeMap();                
        HashSet authorizedcaids = new HashSet(this.authorizationsession.getAuthorizedCAIds(admin));
        TreeMap allhardtokenissuers = this.hardtokensession.getHardTokenIssuers(admin);
        Iterator iter = allhardtokenissuers.keySet().iterator();
        while(iter.hasNext()){          
          String alias = (String) iter.next();
          if(authorizedcaids.contains(new Integer(((HardTokenIssuerData) allhardtokenissuers.get(alias)).getIssuerDN().hashCode()))){                    
		     hardtokenissuers.put(alias,allhardtokenissuers.get(alias));
          }   
        }        
      }
      
      return hardtokenissuers;  
    }
    
    /**
     * Checks if administrator is authorized to edit the specified hard token issuer.
     * 
     * @param alias of hard token issuer
     * @return true if administrator is authorized to edit ahrd token issuer.
     */
    
    public boolean authorizedToHardTokenIssuer(String alias){
    	boolean returnval = false;
    	try{
    	  returnval = this.authorizationsession.isAuthorizedNoLog(admin,"/hardtoken_functionality/edit_hardtoken_issuers");
    	}catch(AuthorizationDeniedException ade){}
    	
    	return returnval && this.getHardTokenIssuers().keySet().contains(alias);    	
    }
    
    public void clear(){      
	  hardtokenissuers=null;
    }    
    
    // Private fields.    
    private TreeMap hardtokenissuers = null;
    
    private Admin admin;
    private IHardTokenSessionLocal hardtokensession;
    private IAuthorizationSessionLocal authorizationsession;    

}


