package se.anatom.ejbca.webdist.cainterface;

import java.io.ByteArrayOutputStream;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.ca.crl.ICreateCRLSessionHome;
import se.anatom.ejbca.apply.RequestHelper;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocal;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocalHome;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.CRLInfo;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.IUserAdminSessionLocalHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.webdist.rainterface.CertificateView;
import se.anatom.ejbca.webdist.rainterface.RevokedInfoView;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;
import se.anatom.ejbca.webdist.webconfiguration.InformationMemory;


/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: CAInterfaceBean.java,v 1.24 2004-03-07 12:15:51 herrvendil Exp $
 */
public class CAInterfaceBean   {


    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() {
    }

    // Public methods
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{

      if(!initialized){
        administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
        InitialContext jndicontext = new InitialContext();
        Object obj1 = jndicontext.lookup("java:comp/env/CertificateStoreSessionLocal");
        ICertificateStoreSessionLocalHome certificatesessionhome = (ICertificateStoreSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionLocalHome.class);
        certificatesession = certificatesessionhome.create();
        
        obj1 = jndicontext.lookup("java:comp/env/CAAdminSessionLocal");
        ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionLocalHome.class);
        caadminsession = caadminsessionhome.create();
        
        IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/AuthorizationSessionLocal"),
                                                                                 IAuthorizationSessionLocalHome.class);
        authorizationsession = authorizationsessionhome.create();
        
        obj1 = jndicontext.lookup("java:comp/env/UserAdminSessionLocal");
        IUserAdminSessionLocalHome adminsessionhome = (IUserAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionLocalHome.class);
        adminsession = adminsessionhome.create();

        IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/RaAdminSessionLocal"),
                                                                                 IRaAdminSessionLocalHome.class);
        raadminsession = raadminsessionhome.create();               
        
		ISignSessionLocalHome home = (ISignSessionLocalHome)javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/SignSessionLocal"), ISignSessionLocalHome.class );
	    signsession = home.create();
	    
	    IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/HardTokenSessionLocal"),
	    		IHardTokenSessionLocalHome.class);
	    hardtokensession = hardtokensessionhome.create();               
	    
	    IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("java:comp/env/PublisherSessionLocal"),
	    		IPublisherSessionLocalHome.class);
	    publishersession = publishersessionhome.create();               
	    
	    
        this.informationmemory = ejbcawebbean.getInformationMemory();
          
        certificateprofiles = new CertificateProfileDataHandler(administrator, certificatesession, authorizationsession, informationmemory);
        cadatahandler = new CADataHandler(administrator, caadminsession, adminsession, raadminsession, certificatesession, authorizationsession, signsession, ejbcawebbean);
        publisherdatahandler = new PublisherDataHandler(administrator, publishersession, authorizationsession, 
        		                                        caadminsession, certificatesession,  informationmemory);
        initialized =true;
      }
    }

    public CertificateView[] getCACertificates(int caid) throws RemoteException, NamingException, CreateException {
      CertificateView[] returnval = null;      
      
      Collection chain = signsession.getCertificateChain(administrator, caid);
      
      returnval = new CertificateView[chain.size()];
      Iterator iter = chain.iterator();
      int i=0;
      while(iter.hasNext()){
        Certificate next = (Certificate) iter.next();  
        RevokedInfoView revokedinfo = null;
        RevokedCertInfo revinfo = certificatesession.isRevoked(administrator, CertTools.getIssuerDN((X509Certificate) next), ((X509Certificate) next).getSerialNumber());
        if(revinfo != null && revinfo.getReason() != RevokedCertInfo.NOT_REVOKED)
          revokedinfo = new RevokedInfoView(revinfo);
        returnval[i] = new CertificateView((X509Certificate) next, revokedinfo,null);
        i++;
      }

      return returnval;
    }
    
    /**
     * Method that returns a HashMap connecting available CAIds (Integer) to CA Names (String).
     *
     */ 
    
    public HashMap getCAIdToNameMap(){
      return informationmemory.getCAIdToNameMap();      
    } 
    
    public Collection getAuthorizedCAs(){
      return informationmemory.getAuthorizedCAIds();
    }  
      
      
    public TreeMap getEditCertificateProfileNames() {
      return informationmemory.getEditCertificateProfileNames();
    }

    /** Returns the profile name from id proxied */
    public String getCertificateProfileName(int profileid) throws RemoteException{
      return this.informationmemory.getCertificateProfileNameProxy().getCertificateProfileName(profileid);
    }
    
    public int getCertificateProfileId(String profilename){
      return certificateprofiles.getCertificateProfileId(profilename);
    }


    public CertificateProfile getCertificateProfile(String name)  throws Exception{
      return certificateprofiles.getCertificateProfile(name);
    }

    public CertificateProfile getCertificateProfile(int id)  throws Exception{
      return certificateprofiles.getCertificateProfile(id);
    }

    public void addCertificateProfile(String name) throws Exception{
       CertificateProfile profile = new CertificateProfile();
       profile.setAvailableCAs(informationmemory.getAuthorizedCAIds());
       
       certificateprofiles.addCertificateProfile(name, profile);
              
    }

   
    public void changeCertificateProfile(String name, CertificateProfile profile) throws Exception {
       certificateprofiles.changeCertificateProfile(name, profile);
    }
    
    /** Returns false if certificate type is used by any user or in profiles. */
    public boolean removeCertificateProfile(String name) throws Exception{

        boolean certificateprofileused = false;
        int certificateprofileid = certificatesession.getCertificateProfileId(administrator, name);        
        CertificateProfile certprofile = this.certificatesession.getCertificateProfile(administrator, name);
        
        if(certprofile.getType() == CertificateProfile.TYPE_ENDENTITY){
          // Check if any users or profiles use the certificate id.
          certificateprofileused = adminsession.checkForCertificateProfileId(administrator, certificateprofileid)
                                || raadminsession.existsCertificateProfileInEndEntityProfiles(administrator, certificateprofileid)
								|| hardtokensession.existsCertificateProfileInHardTokenProfiles(administrator, certificateprofileid);
        }else{
           certificateprofileused = caadminsession.exitsCertificateProfileInCAs(administrator, certificateprofileid);
        }
            
          
        if(!certificateprofileused){
          certificateprofiles.removeCertificateProfile(name);
        }

        return !certificateprofileused;
    }

    public void renameCertificateProfile(String oldname, String newname) throws Exception{
       certificateprofiles.renameCertificateProfile(oldname, newname);
    }

    public void cloneCertificateProfile(String originalname, String newname) throws Exception{
      certificateprofiles.cloneCertificateProfile(originalname, newname);
    }    
      
    public void createCRL(String issuerdn)  throws RemoteException, NamingException, CreateException  {      
      InitialContext jndicontext = new InitialContext();
      ICreateCRLSessionHome home  = (ICreateCRLSessionHome)javax.rmi.PortableRemoteObject.narrow( jndicontext.lookup("CreateCRLSession") , ICreateCRLSessionHome.class );
      home.create().run(administrator, issuerdn);
    }

    public int getLastCRLNumber(String  issuerdn) throws RemoteException   {
      return certificatesession.getLastCRLNumber(administrator, issuerdn);      
    }
    
    public CRLInfo getLastCRLInfo(String issuerdn) throws RemoteException{
      return certificatesession.getLastCRLInfo(administrator,  issuerdn);          
    }

    /* Returns certificateprofiles as a CertificateProfiles object */
    public CertificateProfileDataHandler getCertificateProfileDataHandler(){
      return certificateprofiles;
    }
    
    public HashMap getAvailablePublishers() throws NamingException, CreateException{
      return signsession.getPublisherIdToNameMap(administrator);
    }
    
    public PublisherDataHandler getPublisherDataHandler() {    
    	return this.publisherdatahandler;
    }
    
    public CADataHandler getCADataHandler(){
      return cadatahandler;   
    }
    
    public CAInfoView getCAInfo(String name) throws Exception{
      return cadatahandler.getCAInfo(name);   
    }

    public CAInfoView getCAInfo(int caid) throws Exception{
      return cadatahandler.getCAInfo(caid);   
    }    
    
    public void saveRequestInfo(CAInfo cainfo){
    	this.cainfo = cainfo;
    }
    
    public CAInfo getRequestInfo(){
    	return this.cainfo;
    }
    
	public void savePKCS10RequestData(PKCS10CertificationRequest request){
		this.request = request;
	}
    
	public PKCS10CertificationRequest getPKCS10RequestData(){
		return this.request;
	}    
	
	public String getPKCS10RequestDataAsString() throws Exception{
	  String returnval = null;	
	  if(request != null ){
	  						  				  
 	    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
	    DEROutputStream dOut = new DEROutputStream(bOut);
	    dOut.writeObject(request);
	    dOut.close();
	      	  
	    returnval = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL
	                   + new String(Base64.encode(bOut.toByteArray()))
                       + RequestHelper.END_CERTIFICATE_REQUEST_WITH_NL;  
	    
	  }      
	  return returnval;
   }
    
   public void saveProcessedCertificate(Certificate cert){
	   this.processedcert =cert;
   }
    
   public Certificate getProcessedCertificate(){
	   return this.processedcert;
   }    
	
   public String getProcessedCertificateAsString() throws Exception{
	 String returnval = null;	
	 if(request != null ){
		byte[] b64cert = se.anatom.ejbca.util.Base64.encode(this.processedcert.getEncoded());
		returnval = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;
		returnval += new String(b64cert);
		returnval += RequestHelper.END_CERTIFICATE_WITH_NL;  	    
	 }      
	 return returnval;
  }
    
    // Private methods

    // Private fields
    private ICertificateStoreSessionLocal      certificatesession;
    private ICAAdminSessionLocal               caadminsession;
    private IAuthorizationSessionLocal         authorizationsession;
    private IUserAdminSessionLocal             adminsession;
    private IRaAdminSessionLocal               raadminsession;
    private ISignSessionLocal                  signsession;
    private IHardTokenSessionLocal             hardtokensession;
    private IPublisherSessionLocal             publishersession;
    private CertificateProfileDataHandler      certificateprofiles;
    private CADataHandler                      cadatahandler;
    private PublisherDataHandler               publisherdatahandler;
    private boolean                            initialized;
    private Admin                              administrator;
    private InformationMemory                  informationmemory;
    private CAInfo                                      cainfo;
    private PKCS10CertificationRequest       request;
    private Certificate	                             processedcert;
    
}
