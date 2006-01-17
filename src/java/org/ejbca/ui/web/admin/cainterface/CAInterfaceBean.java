/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.ui.web.admin.cainterface;

import java.io.ByteArrayOutputStream;
import java.rmi.RemoteException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;

import org.bouncycastle.asn1.DEROutputStream;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.protocol.ExtendedPKCS10CertificationRequest;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.ui.web.admin.rainterface.CertificateView;
import org.ejbca.ui.web.admin.rainterface.RevokedInfoView;
import org.ejbca.ui.web.pub.RequestHelper;
import org.ejbca.util.Base64;
import org.ejbca.util.CertTools;


/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id: CAInterfaceBean.java,v 1.1 2006-01-17 20:28:08 anatom Exp $
 */
public class CAInterfaceBean implements java.io.Serializable {


    /** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() {
    }

    // Public methods
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{

      if(!initialized){
        administrator = new Admin(((X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" ))[0]);
        ServiceLocator locator = ServiceLocator.getInstance();
        ICertificateStoreSessionLocalHome certificatesessionhome = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
        certificatesession = certificatesessionhome.create();
        
        ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) locator.getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
        caadminsession = caadminsessionhome.create();
        
        IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
        authorizationsession = authorizationsessionhome.create();
        
        IUserAdminSessionLocalHome adminsessionhome = (IUserAdminSessionLocalHome) locator.getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
        adminsession = adminsessionhome.create();

        IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
        raadminsession = raadminsessionhome.create();               
        
		ISignSessionLocalHome home = (ISignSessionLocalHome)locator.getLocalHome(ISignSessionLocalHome.COMP_NAME );
	    signsession = home.create();
	    
	    IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome)locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
	    hardtokensession = hardtokensessionhome.create();               
	    
	    IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) locator.getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
	    publishersession = publishersessionhome.create();               
	    
	    
        this.informationmemory = ejbcawebbean.getInformationMemory();
          
        certificateprofiles = new CertificateProfileDataHandler(administrator, certificatesession, authorizationsession, informationmemory);
        cadatahandler = new CADataHandler(administrator, caadminsession, adminsession, raadminsession, certificatesession, authorizationsession, signsession, ejbcawebbean);
        publisherdatahandler = new PublisherDataHandler(administrator, publishersession, authorizationsession, 
        		                                        caadminsession, certificatesession,  informationmemory);
        initialized =true;
      }
    }

    public CertificateView[] getCACertificates(int caid) {
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

    /**
     * Return the name of the CA based on its ID
     * @param caId the ca ID
     * @return the name of the CA or null if it does not exists.
     */
    public String getName(Integer caId) {
        return (String)informationmemory.getCAIdToNameMap().get(caId);
    }

    public Collection getAuthorizedCAs(){
      return informationmemory.getAuthorizedCAIds();
    }  
      
      
    public TreeMap getEditCertificateProfileNames() {
      return informationmemory.getEditCertificateProfileNames();
    }

    /** Returns the profile name from id proxied */
    public String getCertificateProfileName(int profileid) {
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

    public int getLastCRLNumber(String  issuerdn) {
      return certificatesession.getLastCRLNumber(administrator, issuerdn);      
    }
    
    public CRLInfo getLastCRLInfo(String issuerdn) {
      return certificatesession.getLastCRLInfo(administrator,  issuerdn);          
    }

    /* Returns certificateprofiles as a CertificateProfiles object */
    public CertificateProfileDataHandler getCertificateProfileDataHandler(){
      return certificateprofiles;
    }
    
    public HashMap getAvailablePublishers() {
      return publishersession.getPublisherIdToNameMap(administrator);
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
    
	public void savePKCS10RequestData(ExtendedPKCS10CertificationRequest request){
		this.request = request;
	}
    
	public ExtendedPKCS10CertificationRequest getPKCS10RequestData(){
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
		byte[] b64cert = Base64.encode(this.processedcert.getEncoded());
		returnval = RequestHelper.BEGIN_CERTIFICATE_WITH_NL;
		returnval += new String(b64cert);
		returnval += RequestHelper.END_CERTIFICATE_WITH_NL;  	    
	 }      
	 return returnval;
  }
   
   public String republish(CertificateView certificatedata){
	String returnval = "CERTREPUBLISHFAILED";
	
	CertReqHistory certreqhist = certificatesession.getCertReqHistory(administrator,certificatedata.getSerialNumberBigInt(), certificatedata.getIssuerDN());
	if(certreqhist != null){
	  CertificateProfile certprofile = certificatesession.getCertificateProfile(administrator,certreqhist.getUserDataVO().getCertificateProfileId());
	  if(certprofile != null){
	    CertificateInfo certinfo = certificatesession.getCertificateInfo(administrator, CertTools.getFingerprintAsString(certificatedata.getCertificate()));
	    if(certprofile.getPublisherList().size() > 0){
	    	if(publishersession.storeCertificate(administrator, certprofile.getPublisherList(), certificatedata.getCertificate(), certreqhist.getUserDataVO().getUsername(), certreqhist.getUserDataVO().getPassword(),
	    			certinfo.getCAFingerprint(), certinfo.getStatus() , certinfo.getType(), certreqhist.getUserDataVO().getExtendedinformation())){
	    		returnval = "CERTREPUBLISHEDSUCCESS";
	    	}
	    }else{
	    	returnval = "NOPUBLISHERSDEFINED";
	    }
	    
	  }else{
	  	returnval = "CERTPROFILENOTFOUND";
	  }	  
	}
	return returnval; 
   }
   
   /** Class used to sort CertReq History by users modfifytime, with latest first*/
   private class CertReqUserCreateComparator implements Comparator{

	public int compare(Object arg0, Object arg1) {		
		return 0 - (((CertReqHistory) arg0).getUserDataVO().getTimeModified().compareTo(
				      ((CertReqHistory) arg1).getUserDataVO().getTimeModified()));
	}
	   
   }
   
   /**
    * Returns a List of CertReqHistUserData from the certreqhist database in an collection sorted by timestamp.
    * 
    */
   public List getCertReqUserDatas(String username){
	   List history = this.certificatesession.getCertReqHistory(administrator, username);
	   
	   // Sort it by timestamp, newest first;
	   Collections.sort(history, new CertReqUserCreateComparator());
	   	   
	   return history;
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
    transient private ExtendedPKCS10CertificationRequest       request;
    private Certificate	                             processedcert;
    
}
