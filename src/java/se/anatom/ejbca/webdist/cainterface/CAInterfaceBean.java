/*
 * CaInterfaceBean.java
 *
 * Created on den 7 maj 2002, 12:06
 */

package se.anatom.ejbca.webdist.cainterface;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.rmi.RemoteException;
import java.util.Properties;
import java.util.Collection;
import java.rmi.RemoteException;
import java.io.IOException;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.ca.store.certificatetypes.CertificateType;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.IJobRunnerSessionHome;

import se.anatom.ejbca.webdist.rainterface.CertificateView;
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.authorization.UserInformation;



/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: CAInterfaceBean.java,v 1.7 2002-08-27 12:41:07 herrvendil Exp $
 */
public class CAInterfaceBean   {

    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() {
    }
    
    // Public methods
    public void initialize(HttpServletRequest request) throws  Exception{

      if(!initialized){
        userinformation = new UserInformation(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);  
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create();
      
        certificatetypes = new CertificateTypeDataHandler(certificatesession); 
        initialized =true; 
      }    
    }
    
    public CertificateView[] getCAInfo() throws RemoteException, NamingException, CreateException {
      CertificateView[] returnval = null;
      InitialContext jndicontext = new InitialContext();
      ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RSASignSession"), ISignSessionHome.class );
      ISignSessionRemote ss = home.create();
      Certificate[] chain = ss.getCertificateChain();

      if(chain != null){
        returnval = new CertificateView[chain.length];
        for(int i = 0; i < chain.length; i++){
          RevokedInfoView revokedinfo = null;
          RevokedCertInfo revinfo = certificatesession.isRevoked(((X509Certificate) chain[i]).getIssuerDN().toString(), ((X509Certificate) chain[i]).getSerialNumber());
          if(revinfo != null)
            revokedinfo = new RevokedInfoView(revinfo);
          returnval[i] = new CertificateView((X509Certificate) chain[i], revokedinfo);
        }
      }

      return returnval;
    }

    public void createCRL()  throws RemoteException, NamingException, CreateException  {
      InitialContext jndicontext = new InitialContext();        
      IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
      home.create().run();
    }

    public int getLastCRLNumber() throws RemoteException   {
      return certificatesession.getLastCRLNumber();
    }
 
    // Methods dealing with certificate types.

    public String[] getCertificateTypeNames() throws RemoteException{
      return certificatetypes.getCertificateTypeNames();
    }
    
    public int getCertificateTypeId(String certificatetypename) throws RemoteException{
      return certificatetypes.getCertificateTypeId(certificatetypename);   
    }

    /* Returns certificatetypes as a CertificateTypes object */
    public CertificateTypeDataHandler getCertificateTypeDataHandler(){
      return certificatetypes;
    }

    public CertificateType getCertificateType(String name) throws RemoteException{
      return certificatetypes.getCertificateType(name);
    }

    public void addCertificateType(String name) throws CertificateTypeExistsException, RemoteException{
       certificatetypes.addCertificateType(name, new CertificateType());
    }

    public void addCertificateType(String name, CertificateType certificatetype) throws CertificateTypeExistsException, RemoteException {
       certificatetypes.addCertificateType(name, certificatetype);
    }

    public void changeCertificateType(String name, CertificateType certificatetype) throws CertificateTypeDoesntExistsException, RemoteException {
       certificatetypes.changeCertificateType(name, certificatetype);
    }
    
    /** Returns false if certificate type is used by any user or in profiles. */
    public boolean removeCertificateType(String name) throws Exception{
        InitialContext jndicontext = new InitialContext();              
        Object obj1 = jndicontext.lookup("UserAdminSession");
        IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSessionRemote adminsession = adminsessionhome.create();
        adminsession.init(userinformation);
      
        obj1 = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
        IRaAdminSessionRemote raadminsession = raadminsessionhome.create(); 
        
        
        boolean certificatetypeused = false;
        int certificatetypeid = certificatesession.getCertificateTypeId(name);
        // Check if any users or profiles use the certificate id.
        certificatetypeused = adminsession.checkForCertificateTypeId(certificatetypeid) 
                            || raadminsession.existsCertificateTypeInProfiles(certificatetypeid); 

        if(!certificatetypeused){
          certificatetypes.removeCertificateType(name);
        }
        
        return !certificatetypeused;       
    }

    public void renameCertificateType(String oldname, String newname) throws CertificateTypeExistsException, RemoteException{
       certificatetypes.renameCertificateType(oldname, newname);
    }

    public void cloneCertificateType(String originalname, String newname) throws CertificateTypeExistsException, RemoteException{
      certificatetypes.cloneCertificateType(originalname, newname);
    }
    

    // Private methods

    // Private fields
    private ICertificateStoreSessionRemote    certificatesession;
    private ICertificateStoreSessionHome      certificatesessionhome;
    private CertificateTypeDataHandler        certificatetypes;
    private boolean                           initialized;
    private UserInformation                   userinformation;

}
