package se.anatom.ejbca.webdist.cainterface;

import javax.naming.*;
import javax.ejb.CreateException;
import java.rmi.RemoteException;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.IJobRunnerSessionHome;

import se.anatom.ejbca.webdist.rainterface.CertificateView;
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.log.Admin;


/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: CAInterfaceBean.java,v 1.12 2003-01-12 17:16:34 anatom Exp $
 */
public class CAInterfaceBean   {

    
    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() {
    }
    
    // Public methods
    public void initialize(HttpServletRequest request) throws  Exception{

      if(!initialized){
        administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);  
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        certificatesession = certificatesessionhome.create();
      
        certificateprofiles = new CertificateProfileDataHandler(certificatesession, administrator); 
        initialized =true; 
      }    
    }
    
    public CertificateView[] getCAInfo() throws RemoteException, NamingException, CreateException {
      CertificateView[] returnval = null;
      InitialContext jndicontext = new InitialContext();
      ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RSASignSession"), ISignSessionHome.class );
      ISignSessionRemote ss = home.create();
      Certificate[] chain = ss.getCertificateChain(administrator);

      if(chain != null){
        returnval = new CertificateView[chain.length];
        for(int i = 0; i < chain.length; i++){
          RevokedInfoView revokedinfo = null;
          RevokedCertInfo revinfo = certificatesession.isRevoked(administrator, ((X509Certificate) chain[i]).getIssuerDN().toString(), ((X509Certificate) chain[i]).getSerialNumber());
          if(revinfo != null)
            revokedinfo = new RevokedInfoView(revinfo);
          returnval[i] = new CertificateView((X509Certificate) chain[i], revokedinfo,null);
        }
      }

      return returnval;
    }

    public void createCRL()  throws RemoteException, NamingException, CreateException  {
      InitialContext jndicontext = new InitialContext();        
      IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
      home.create().run(administrator);
    }

    public int getLastCRLNumber() throws RemoteException   {
      return certificatesession.getLastCRLNumber(administrator);
    }
 
    // Methods dealing with certificate types.

    public String[] getCertificateProfileNames() throws RemoteException{
      return certificateprofiles.getCertificateProfileNames();
    }
    
    public int getCertificateProfileId(String certificateprofilename) throws RemoteException{
      return certificateprofiles.getCertificateProfileId(certificateprofilename);   
    }

    /* Returns certificateprofiles as a CertificateProfiles object */
    public CertificateProfileDataHandler getCertificateProfileDataHandler(){
      return certificateprofiles;
    }

    public CertificateProfile getCertificateProfile(String name) throws RemoteException{
      return certificateprofiles.getCertificateProfile(name);
    }

    public void addCertificateProfile(String name) throws CertificateProfileExistsException, RemoteException{
       certificateprofiles.addCertificateProfile(name, new CertificateProfile());
    }

    public void addCertificateProfile(String name, CertificateProfile certificateprofile) throws CertificateProfileExistsException, RemoteException {
       certificateprofiles.addCertificateProfile(name, certificateprofile);
    }

    public void changeCertificateProfile(String name, CertificateProfile certificateprofile) throws CertificateProfileDoesntExistsException, RemoteException {
       certificateprofiles.changeCertificateProfile(name, certificateprofile);
    }
    
    /** Returns false if certificate type is used by any user or in profiles. */
    public boolean removeCertificateProfile(String name) throws Exception{
        InitialContext jndicontext = new InitialContext();              
        Object obj1 = jndicontext.lookup("UserAdminSession");
        IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSessionRemote adminsession = adminsessionhome.create();
      
        obj1 = jndicontext.lookup("RaAdminSession");
        IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
        IRaAdminSessionRemote raadminsession = raadminsessionhome.create(); 
        
        
        boolean certificateprofileused = false;
        int certificateprofileid = certificatesession.getCertificateProfileId(administrator, name);
        // Check if any users or profiles use the certificate id.
        certificateprofileused = adminsession.checkForCertificateProfileId(administrator, certificateprofileid) 
                            || raadminsession.existsCertificateProfileInEndEntityProfiles(administrator, certificateprofileid); 

        if(!certificateprofileused){
          certificateprofiles.removeCertificateProfile(name);
        }
        
        return !certificateprofileused;       
    }

    public void renameCertificateProfile(String oldname, String newname) throws CertificateProfileExistsException, RemoteException{
       certificateprofiles.renameCertificateProfile(oldname, newname);
    }

    public void cloneCertificateProfile(String originalname, String newname) throws CertificateProfileExistsException, RemoteException{
      certificateprofiles.cloneCertificateProfile(originalname, newname);
    }
    

    // Private methods

    // Private fields
    private ICertificateStoreSessionRemote    certificatesession;
    private ICertificateStoreSessionHome      certificatesessionhome;
    private CertificateProfileDataHandler     certificateprofiles;
    private boolean                           initialized;
    private Admin                             administrator;

}
