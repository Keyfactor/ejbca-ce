/*
 * SubjectDNProxy.java
 *
 * Created on den 29 august 2002, 17:49
 */

package se.anatom.ejbca.webdist.loginterface;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import javax.naming.*;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Collection;
import java.math.BigInteger;
import java.security.cert.X509Certificate;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.log.Admin;

/**
 * A class used to improve performance by proxying certificatesnr to subjectdn mappings by minimizing the number of needed lockups over rmi.
 * 
 * @author  TomSelleck
 */
public class SubjectDNProxy {
    
    /** Creates a new instance of SubjectDNProxy with remote access to CA part */
    public SubjectDNProxy(Admin admin, ICertificateStoreSessionRemote certificatesession){
              // Get the RaAdminSession instance.
      this.local = false;
      this.certificatesessionremote = certificatesession;
      this.subjectdnstore = new HashMap(); 
      this.admin = admin;
        
    }
    
    /** Creates a new instance of SubjectDNProxy with local access to CA part */
    public SubjectDNProxy(ICertificateStoreSessionLocal certificatesession){
              // Get the RaAdminSession instance.
      this.local = true;
      this.certificatesessionlocal = certificatesession;
      this.subjectdnstore = new HashMap(); 
        
    }    
    
    /**
     * Method that first tries to find subjectDN in local hashmap and if it doesn't exists looks it up over RMI.
     *
     * @param certificatesnr the certificate serial number number to look up.
     * @return the subjectDN or null if no subjectDN is relatied to the given id
     */
    public String getSubjectDN(String certificatesnr) throws RemoteException {
      String returnval = null; 
      Collection result = null;
      // Check if name is in hashmap
      returnval = (String) subjectdnstore.get(certificatesnr);
      
      if(returnval==null){
        // Retreive subjectDN over RMI
        if(local)  
          result = certificatesessionlocal.findCertificatesBySerno(admin, new BigInteger(certificatesnr,16));
        else
          result = certificatesessionremote.findCertificatesBySerno(admin, new BigInteger(certificatesnr, 16));            
        if(result != null){
          Iterator i = result.iterator();
          if(i.hasNext()){
            returnval = ((X509Certificate) i.next()).getSubjectDN().toString();  
            subjectdnstore.put(certificatesnr,returnval);
          }  
        }  
      }    
       
      return returnval;
    }

    // Private fields
    private boolean local;
    private HashMap subjectdnstore;
    private ICertificateStoreSessionLocal  certificatesessionlocal;
    private ICertificateStoreSessionRemote certificatesessionremote;
    private Admin                          admin;

}
