package se.anatom.ejbca.webdist.cainterface;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;

import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.exception.CAExistsException;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.protocol.IRequestMessage;
import se.anatom.ejbca.protocol.IResponseMessage;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
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
                         EjbcaWebBean ejbcawebbean) {
                            
       this.caadminsession = caadminsession;           
       this.authorizationsession = authorizationsession;
       this.adminsession = adminsession;
       this.certificatesession = certificatesession;
       this.raadminsession = raadminsession;
       this.administrator = administrator;          
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
  public IRequestMessage  makeRequest(Admin admin, int caid, Collection cachain, boolean setstatustowaiting) throws CADoesntExistsException, AuthorizationDeniedException{
      // Todo
      info.cAsEdited();
      
      return null;
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void receiveResponse(Admin admin, int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException{
     // TODO 
     info.cAsEdited(); 
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public Collection processRequest(Admin admin, String username, String password, IRequestMessage requestmessage) throws CADoesntExistsException, AuthorizationDeniedException{
      // Todo
      info.cAsEdited();
      
      return null;      
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void renewCA(int caid, IResponseMessage responsemessage) throws CADoesntExistsException, AuthorizationDeniedException{
      // Todo      
      info.cAsEdited();
  }

  /**
   *  @see se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal
   */  
  public void revokeCA(int caid, int reason) throws CADoesntExistsException, AuthorizationDeniedException{
      // Todo
      info.cAsEdited();
  }
      
   
  private ICAAdminSessionLocal           caadminsession; 
  private Admin                          administrator;
  private IAuthorizationSessionLocal     authorizationsession;
  private InformationMemory              info;
  private IUserAdminSessionLocal         adminsession;
  private IRaAdminSessionLocal           raadminsession; 
  private ICertificateStoreSessionLocal  certificatesession;                          
  private EjbcaWebBean                   ejbcawebbean;
}
