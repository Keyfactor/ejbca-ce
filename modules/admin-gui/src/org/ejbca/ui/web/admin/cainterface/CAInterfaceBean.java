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

import java.rmi.RemoteException;
import java.security.cert.Certificate;
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

import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.ejb.ServiceLocator;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.crl.CreateCRLSession;
import org.ejbca.core.ejb.ca.publisher.PublisherQueueSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.sign.SignSession;
import org.ejbca.core.ejb.ca.store.CertificateStatus;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSession;
import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.ui.web.CertificateView;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.ui.web.RevokedInfoView;
import org.ejbca.ui.web.admin.configuration.EjbcaWebBean;
import org.ejbca.ui.web.admin.configuration.InformationMemory;
import org.ejbca.util.CertTools;


/**
 * A class used as an interface between CA jsp pages and CA ejbca functions.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class CAInterfaceBean implements java.io.Serializable {

	private static final long serialVersionUID = 2L;
	
	private EjbLocalHelper ejb = new EjbLocalHelper();
	
	/** Creates a new instance of CaInterfaceBean */
    public CAInterfaceBean() {
    }

    // Public methods
    public void initialize(EjbcaWebBean ejbcawebbean) throws  Exception{

        if(!initialized){
          ServiceLocator locator = ServiceLocator.getInstance();
          certificatesession = ejb.getCertStoreSession();
          createCrlSession = ejb.getCreateCrlSession();
          caadminsession = ejb.getCAAdminSession();
          authorizationsession = ejb.getAuthorizationSession();
          adminsession = ejb.getUserAdminSession();
          raadminsession = ejb.getRAAdminSession();               
          signsession = ejb.getSignSession();
          hardtokensession = ejb.getHardTokenSession();               
          publishersession = ejb.getPublisherSession();               
          publisherqueuesession = ejb.getPublisherQueueSession();
  	      	    
          this.informationmemory = ejbcawebbean.getInformationMemory();
          this.administrator = ejbcawebbean.getAdminObject();
            
          certificateprofiles = new CertificateProfileDataHandler(administrator, certificatesession, authorizationsession, caadminsession, informationmemory);
          cadatahandler = new CADataHandler(administrator, caadminsession, adminsession, raadminsession, certificatesession, authorizationsession, createCrlSession, ejbcawebbean);
          publisherdatahandler = new PublisherDataHandler(administrator, publishersession, authorizationsession, caadminsession, certificatesession,  informationmemory);
          isUniqueIndex = signsession.isUniqueCertificateSerialNumberIndex();
          initialized =true;
        }
      }
    public void initialize(HttpServletRequest request, EjbcaWebBean ejbcawebbean) throws  Exception{
    	initialize(ejbcawebbean);
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
        CertificateStatus revinfo = certificatesession.getStatus(CertTools.getIssuerDN(next), CertTools.getSerialNumber(next));
        if(revinfo != null && revinfo.revocationReason != RevokedCertInfo.NOT_REVOKED) {
          revokedinfo = new RevokedInfoView(revinfo, CertTools.getSerialNumber(next));
        }
        returnval[i] = new CertificateView(next, revokedinfo,null);
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
      
    public void createCRL(String issuerdn)  throws RemoteException, NamingException, CreateException, CATokenOfflineException  {      
      InitialContext jndicontext = new InitialContext();
      CA ca;
		try {
			ca = caadminsession.getCA(administrator, issuerdn.hashCode());
		} catch (CADoesntExistsException e) {
			throw new RuntimeException(e);
		}
      createCrlSession.run(administrator, ca);
    }
    public void createDeltaCRL(String issuerdn)  throws RemoteException, NamingException, CreateException  {      
    	InitialContext jndicontext = new InitialContext();
        CA ca;
		try {
			ca = caadminsession.getCA(administrator, issuerdn.hashCode());
		} catch (CADoesntExistsException e) {
			throw new RuntimeException(e);
		}
    	createCrlSession.runDeltaCRL(administrator, ca, -1, -1);
    }

    public int getLastCRLNumber(String  issuerdn) {
      return createCrlSession.getLastCRLNumber(administrator, issuerdn, false);      
    }

    /**
     * @param caInfo of the CA that has issued the CRL.
     * @param deltaCRL false for complete CRL info, true for delta CRLInfo
     * @return CRLInfo of last CRL by CA or null if no CRL exists.
     */
	public CRLInfo getLastCRLInfo(CAInfo caInfo, boolean deltaCRL) {
		final String issuerdn;// use issuer DN from CA certificate. Might differ from DN in CAInfo.
		{
			final Collection certs = caInfo.getCertificateChain();
			final Certificate cacert = !certs.isEmpty() ? (Certificate)certs.iterator().next(): null;
			issuerdn = cacert!=null ? CertTools.getSubjectDN(cacert) : null;
		}
		return createCrlSession.getLastCRLInfo(administrator,  issuerdn, deltaCRL);          
	}

    /* Returns certificate profiles as a CertificateProfiles object */
    public CertificateProfileDataHandler getCertificateProfileDataHandler(){
      return certificateprofiles;
    }
    
    public HashMap getAvailablePublishers() {
      return publishersession.getPublisherIdToNameMap(administrator);
    }
    
    public int getPublisherQueueLength(int publisherId) {
    	return publisherqueuesession.getPendingEntriesCountForPublisher(publisherId);
    }
    
    public int[] getPublisherQueueLength(int publisherId, int[] intervalLower, int[] intervalUpper) {
    	return publisherqueuesession.getPendingEntriesCountForPublisherInIntervals(publisherId, intervalLower, intervalUpper);
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
    
	public void saveRequestData(byte[] request){
		this.request = request;
	}
    
	public byte[] getRequestData(){
		return this.request;
	}    
	
	public String getRequestDataAsString() throws Exception{
	  String returnval = null;	
	  if(request != null ){
	  						  				  
	    returnval = RequestHelper.BEGIN_CERTIFICATE_REQUEST_WITH_NL
	                   + new String(Base64.encode(request))
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
	    	if(publishersession.storeCertificate(administrator, certprofile.getPublisherList(), certificatedata.getCertificate(), certreqhist.getUserDataVO().getUsername(), certreqhist.getUserDataVO().getPassword(), certreqhist.getUserDataVO().getDN(),
	    			certinfo.getCAFingerprint(), certinfo.getStatus() , certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certinfo.getTag(), certinfo.getCertificateProfileId(), certinfo.getUpdateTime().getTime(), certreqhist.getUserDataVO().getExtendedinformation())){
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
    
   /**
    *  Help functions used by edit certificate profile pages used to temporary
    *  save a profile so things can be canceled later.
    */
   public CertificateProfile getTempCertificateProfile(){
	   return this.tempCertProfile;
   }

   public void setTempCertificateProfile(CertificateProfile profile){
	   this.tempCertProfile = profile;
   }
   
   /**
    * @return true if serial number unique indexing is supported by DB.
    */
   public boolean isUniqueIndexForSerialNumber() {
       return this.isUniqueIndex;
   }
   
   // Private methods

    // Private fields
    private CertificateStoreSession      certificatesession;
    private CAAdminSession               caadminsession;
    private CreateCRLSession             createCrlSession;
    private AuthorizationSession         authorizationsession;
    private UserAdminSession             adminsession;
    private RaAdminSession               raadminsession;
    private SignSession                  signsession;
    private HardTokenSession             hardtokensession;
    private PublisherSession             publishersession;
    private PublisherQueueSession        publisherqueuesession;
    private CertificateProfileDataHandler      certificateprofiles;
    private CADataHandler                      cadatahandler;
    private PublisherDataHandler               publisherdatahandler;
    private boolean                            initialized;
    private Admin                              administrator;
    private InformationMemory                  informationmemory;
    private CAInfo                                      cainfo;
    /** The certification request in binary format */
    transient private byte[]       request;
    private Certificate	                             processedcert;
    private CertificateProfile                 tempCertProfile = null;
	private boolean isUniqueIndex;
}
