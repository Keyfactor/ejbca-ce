package se.anatom.ejbca.webdist.hardtokeninterface;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
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
 * @version $Id: HardTokenAuthorization.java,v 1.2 2003-12-05 14:50:27 herrvendil Exp $
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
	 * Method returning a TreeMap containing Hard Token Profile Name -> Hard Token Profile Data
	 * the administrator is authorized to view and edit
	 * @return A TreeMap Hard Token Profile Name (String) -> HardTokenProfile
	 */    
	public TreeMap getHardTokenProfiles(){  
	  if(hardtokenprofiles==null){            
		hardtokenprofiles = new TreeMap();                
		Collection authorizedhardtokenprofiles = hardtokensession.getAuthorizedHardTokenProfileIds(admin);
		
		Iterator iter = authorizedhardtokenprofiles.iterator();
		while(iter.hasNext()){
		  int id = ((Integer) iter.next()).intValue();	          
		  String name = hardtokensession.getHardTokenProfileName(admin,id);
		  hardtokenprofiles.put(hardtokensession.getHardTokenProfileName(admin,id),
		                        hardtokensession.getHardTokenProfile(admin,id));
		    
		}        
	  }
      
	  return hardtokenprofiles;  
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

	/**
	 * Checks if administrator is authorized to edit the specified hard token profile.
	 * 
	 * @param alias of hard token profile
	 * @return true if administrator is authorized to edit hard token profile.
	 */
    
	public boolean authorizedToHardTokenProfile(String name){
		boolean returnval = false;
		try{
		  returnval = this.authorizationsession.isAuthorizedNoLog(admin,"/hardtoken_functionality/edit_hardtoken_profiles");
		}catch(AuthorizationDeniedException ade){}
    	
		return returnval && this.getHardTokenProfiles().keySet().contains(name);    	
	}

    
	/**
	 * Returns a Map of hard token profile id (Integer) -> hard token profile name (String).
	 */
	public HashMap getHardTokenProfileIdToNameMap(){
	  if(hardtokenprofilesnamemap == null){
		hardtokenprofilesnamemap = this.hardtokensession.getHardTokenProfileIdToNameMap(admin); 
	  }
      
	  return hardtokenprofilesnamemap;
	}        
    
    public void clear(){      
	  hardtokenissuers=null;
	  hardtokenprofiles=null;
	  hardtokenprofilesnamemap=null;
    }    
    
    // Private fields.    
    private TreeMap hardtokenissuers = null;
	private TreeMap hardtokenprofiles = null;
	private HashMap hardtokenprofilesnamemap=null;
	
    private Admin admin;
    private IHardTokenSessionLocal hardtokensession;
    private IAuthorizationSessionLocal authorizationsession;    

}


