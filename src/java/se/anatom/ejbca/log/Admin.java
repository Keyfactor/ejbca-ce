/*
 * Admin.java
 *
 * Created on den 25 august 2002, 10:02
 */

package se.anatom.ejbca.log;

import java.security.cert.X509Certificate;
import se.anatom.ejbca.ra.authorization.UserEntity;
import se.anatom.ejbca.ra.authorization.UserInformation;
/**
 *  This is a class containing information about the administrator or user preforming the event. 
 *  Data contained in the class is preferbly
 *
 *  
 *
 * @author  TomSelleck
 */
public class Admin implements java.io.Serializable {
  
    // Public Constants
    // Indicates the type of administrator.
    public static final int TYPE_CLIENTCERT_USER       = 0;
    public static final int TYPE_PUBLIC_WEB_USER       = 1;
    public static final int TYPE_RACOMMANDLINE_USER    = 2;
    public static final int TYPE_CACOMMANDLINE_USER    = 3;   
    public static final int TYPE_BATCHCOMMANDLINE_USER = 4; 
    public static final int TYPE_INTERNALUSER          = 5;     

    public static final int SPECIAL_ADMIN_BOUNDRARY = 100;
    
    public static final String[] ADMINTYPETEXTS = {"CLIENTCERT","PUBLICWEBUSER","RACMDLINE","CACMDLINE","BATCHCMDLINE", "INTERNALUSER"};
        
    private int[] ADMINTYPETOADMINENTIRY = {0, UserEntity.SPECIALUSER_PUBLICWEBUSER, UserEntity.SPECIALUSER_CACOMMANDLINEADMIN, 
                                               UserEntity.SPECIALUSER_RACOMMANDLINEADMIN, UserEntity.SPECIALUSER_BATCHCOMMANDLINEADMIN,
                                               UserEntity.SPECIALUSER_INTERNALUSER};
                                                         
    
    // Public Constructors
    public Admin(X509Certificate certificate){
      this.type=TYPE_CLIENTCERT_USER;
      this.data= certificate.getSerialNumber().toString(16);        
      this.certificate = certificate;
    }
    
    public Admin(int type, String ip){
      this.type=type;
      this.data=ip;  
    }
    
    public Admin(int type){
      this.type=type;
      this.data=null;    
    }

    // Public Methods    
    
    public int getAdminType(){
      return this.type;         
    }
    
    public String getAdminData(){
      return this.data;   
    }
        
    // Method that takes the internal data and returns a UserInformation object required by the Authorization module.
    public UserInformation getUserInformation(){
       if(type == TYPE_CLIENTCERT_USER)
         return new UserInformation(certificate);
       
       return new UserInformation( ADMINTYPETOADMINENTIRY[type]);
    }
    
    
    // Private Methods
    
    // Private fields
    private    int             type = 0;
    private    String          data = null;   
    private    X509Certificate certificate =null;
}
