/*
 * ProfileNameProxy.java
 *
 * Created on den 23 juli 2002, 17:49
 */

package se.anatom.ejbca.webdist.cainterface;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import javax.naming.*;
import java.util.HashMap;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.log.Admin;
/**
 * A class used to improve performance by proxying certificatetype id to certificate name mappings by minimizing the number of needed lockups over rmi.
 * 
 * @author  TomSelleck
 */
public class CertificateTypeNameProxy {
    
    /** Creates a new instance of ProfileNameProxy */
    public CertificateTypeNameProxy(Admin administrator) throws Exception {
              // Get the RaAdminSession instance.
      InitialContext jndicontext = new InitialContext();
      Object obj1 = jndicontext.lookup("CertificateStoreSession");
      ICertificateStoreSessionHome certificatestoresessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(
                                                                                 jndicontext.lookup("CertificateStoreSession"), 
                                                                                 ICertificateStoreSessionHome.class);
      certificatestoresession = certificatestoresessionhome.create(administrator);  
      
      certificatetypenamestore = new HashMap(); 
        
    }
    
    /**
     * Method that first tries to find certificatetype name in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param certificatetypeid the certificatetype id number to look up.
     * @return the certificatetypename or null if no certificatetypename is relatied to the given id
     */
    public String getCertificateTypeName(int certificatetypeid) throws RemoteException {
      String returnval = null;  
      // Check if name is in hashmap
      returnval = (String) certificatetypenamestore.get(new Integer(certificatetypeid));
      
      if(returnval==null){
        // Retreive profilename over RMI
        returnval = certificatestoresession.getCertificateTypeName(certificatetypeid);
        if(returnval != null)
          certificatetypenamestore.put(new Integer(certificatetypeid),returnval);
      }    
       
      return returnval;
    }
    
    // Private fields
    private HashMap certificatetypenamestore;
    private ICertificateStoreSessionRemote certificatestoresession;

}
