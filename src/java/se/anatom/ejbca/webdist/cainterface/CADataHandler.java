package se.anatom.ejbca.webdist.cainterface;

import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.certificateprofiles.CertificateProfile;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.protocol.PKCS10RequestMessage;
import se.anatom.ejbca.protocol.X509ResponseMessage;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.webdist.webconfiguration.EjbcaWebBean;
import se.anatom.ejbca.webdist.webconfiguration.InformationMemory;

/**
 * A class help administrating CAs. 
 *
 * @author  TomSelleck
 */
public class CADataHandler implements Serializable {

    
    /** Creates a new instance of CertificateProfileDataHandler */
    public CADataHandler(Admin administrator, 
                         ICAAdminSessionLocal caadminsession, 
                         IUserAdminSessionLocal adminsession, 
                         IRaAdminSessionLocal raadminsession, 
                         ICertificateStoreSessionLocal certificatesession,
                         IAuthorizationSessionLocal authorizationsession,
                         ISignSessionLocal signsession,
                         EjbcaWebBean ejbcawebbean) {
                            
       this.caadminsession = caadminsession;           
       this.authorizationsession = authorizationsession;
       this.adminsession = adminsession;
       this.certificatesession = certificatesession;
       this.raadminsession = raadminsession;
       this.administrator = administrator;          
       this.signsession = signsession;
       this.info = ejbcawebbean.getInformationMemory();       
       this.ejbcawebbean = ejbcawebbean;
    }
    
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */    
  public void createCA(CAInfo cainfo) throws CAExistsException, AuthorizationDeniedException{
    caadminsession.createCA(administrator, cainfo);
    info.cAsEdited();
  }
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */
  public void editCA(CAInfo cainfo) throws AuthorizationDeniedException{
    caadminsession.editCA(administrator, cainfo);  
    info.cAsEdited();
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public boolean removeCA(int caid) throws AuthorizationDeniedException{
      
    boolean caidexits = this.adminsession.checkForCAId(administrator, caid) ||
                        this.certificatesession.existsCAInCertificateProfiles(administrator, caid) ||
                        this.raadminsession.existsCAInEndEntityProfiles(administrator, caid) ||
                        this.authorizationsession.existsCAInRules(administrator, caid);
     
    if(!caidexits){
      caadminsession.removeCA(administrator, caid);
      info.cAsEdited();
    }
    
    return !caidexits;
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void renameCA(String oldname, String newname) throws CAExistsException, AuthorizationDeniedException{
    caadminsession.renameCA(administrator, oldname, newname);  
    info.cAsEdited();
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public CAInfoView getCAInfo(String name) throws Exception{
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caadminsession.getCAInfo(administrator, name);
    if(cainfo != null)
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    
    return cainfoview;
  }
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public CAInfoView getCAInfo(int caid) throws Exception{
    // temporate        
    CAInfoView cainfoview = null; 
    CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
    if(cainfo != null)
      cainfoview = new CAInfoView(cainfo, ejbcawebbean, info.getPublisherIdToNameMap());
    
    return cainfoview;  
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public HashMap getCAIdToNameMap(){
    return info.getCAIdToNameMap();
  }
  
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public PKCS10CertificationRequest  makeRequest(int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException{
  	
	  PKCS10RequestMessage result = (PKCS10RequestMessage) caadminsession.makeRequest(administrator, caid,cachain,setstatustowaiting);
	  return result.getCertificationRequest();    
  }	    

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void receiveResponse(int caid, InputStream is) throws Exception{
  	 Collection certs = CertTools.getCertsFromPEM(is);
  	 Iterator iter = certs.iterator();
  	 Certificate cert = (Certificate) iter.next();
  	 X509ResponseMessage resmes = new X509ResponseMessage();
  	 resmes.setCertificate(cert);
  
     caadminsession.receiveResponse(administrator, caid, resmes);
     info.cAsEdited(); 
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public Certificate processRequest(CAInfo cainfo, IRequestMessage requestmessage) throws Exception {      
      Certificate returnval = null;
      IResponseMessage result = caadminsession.processRequest(administrator, cainfo, requestmessage);
      if(result instanceof X509ResponseMessage){
         returnval = ((X509ResponseMessage) result).getCertificate();      
      }            
      info.cAsEdited();
      
      return returnval;      
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void renewCA(int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException, CertPathValidatorException{
      caadminsession.renewCA(administrator, caid, responsemessage);
      info.cAsEdited();
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void revokeCA(int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException{
      caadminsession.revokeCA(administrator, caid, reason);
      info.cAsEdited();
  }
      
  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
 public void publishCA(int caid){
 	CAInfo cainfo = caadminsession.getCAInfo(administrator, caid);
 	CertificateProfile certprofile = certificatesession.getCertificateProfile(administrator, cainfo.getCertificateProfileId());
 	signsession.publishCACertificate(administrator, cainfo.getCertificateChain(), certprofile.getPublisherList() , cainfo.getSignedBy() == CAInfo.SELFSIGNED);
 }
   
  private ICAAdminSessionLocal           caadminsession; 
  private Admin                          administrator;
  private IAuthorizationSessionLocal     authorizationsession;
  private InformationMemory              info;
  private IUserAdminSessionLocal         adminsession;
  private IRaAdminSessionLocal           raadminsession; 
  private ICertificateStoreSessionLocal  certificatesession;                          
  private EjbcaWebBean                   ejbcawebbean;
  private ISignSessionLocal               signsession;
}
