/*
 * CertificateTypeDataHandler.java
 *
 * Created on den 30 juli 2002, 13:03
 */

package se.anatom.ejbca.webdist.cainterface;

import java.io.IOException;
import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Collection;
import java.util.Iterator;
import java.util.TreeMap;
import java.io.Serializable;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.certificatetypes.CertificateType;
/**
 * A class handling the certificate type data. It saves and retrieves them currently from a database.
 *
 * @author  TomSelleck
 */
public class CertificateTypeDataHandler implements Serializable {

    public static final int FIXED_CERTIFICATETYPE_BOUNDRY        = ICertificateStoreSessionRemote.FIXED_CERTIFICATETYPE_BOUNDRY;    
    /** Creates a new instance of CertificateTypeDataHandler */
    public CertificateTypeDataHandler(ICertificateStoreSessionRemote certificatesession) throws RemoteException, FinderException{

       certificatestoresession = certificatesession;               
 
       Collection certificatetypenames = certificatestoresession.getCertificateTypeNames();
       
    }
        
       /** Method to add a certificatetype. Throws CertificateTypeExitsException if certificatetype already exists  */
    public void addCertificateType(String name, CertificateType certificatetype) throws CertificateTypeExistsException, RemoteException {
      if(!certificatestoresession.addCertificateType(name,certificatetype))   
        throw new CertificateTypeExistsException(name);
    }
      
       /** Method to change a  certificatetype. Throws CertificateTypeDoesntExitsException if certificatetype cannot be found */     
    public void changeCertificateType(String name, CertificateType certificatetype) throws CertificateTypeDoesntExistsException, RemoteException {
       if(!certificatestoresession.changeCertificateType(name,certificatetype))
         throw new CertificateTypeDoesntExistsException(name); 
    }
    
    /** Method to remove a certificatetype.*/ 
    public void removeCertificateType(String name) throws RemoteException{
        certificatestoresession.removeCertificateType(name);
    }
    
    /** Metod to rename a certificatetype */
    public void renameCertificateType(String oldname, String newname) throws CertificateTypeExistsException, RemoteException{
      if(!certificatestoresession.renameCertificateType(oldname,newname))   
        throw new CertificateTypeExistsException(newname);
    }
    
    
      /** Method to get a reference to a certificatetype.*/ 
    public CertificateType getCertificateType(String name) throws RemoteException {
        return certificatestoresession.getCertificateType(name);
    }  
        
    /** Returns the number of certificatetypes i database. */
    public int getNumberOfCertificateTypes() throws RemoteException {
      return certificatestoresession.getNumberOfCertificateTypes();
    }
    
    /** Returns an array containing all the certificatetypes names.*/
     public String[] getCertificateTypeNames() throws RemoteException {
      String[] dummy={}; 
      TreeMap result = certificatestoresession.getCertificateTypes();      
      return (String[]) result.keySet().toArray(dummy);  
    }
    
    /** Returns an array containing all the certificatetypes.*/
    public CertificateType[] getCertificateTypes() throws RemoteException {
      CertificateType[] dummy={}; 
      TreeMap result = certificatestoresession.getCertificateTypes();      
      return (CertificateType[]) result.values().toArray(dummy);   
    }
        
    
    public void cloneCertificateType(String originalname, String newname) throws CertificateTypeExistsException, RemoteException{         
      // Check if original certificatetype already exists. 
      if(!certificatestoresession.cloneCertificateType(originalname,newname)){
        throw new CertificateTypeExistsException(newname);        
      }       
    }
    
    public int getCertificateTypeId(String certificatetypename) throws RemoteException{
      return certificatestoresession.getCertificateTypeId(certificatetypename);  
    }
   
    private ICertificateStoreSessionRemote certificatestoresession; 
}
