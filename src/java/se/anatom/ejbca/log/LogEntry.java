/*
 * LogEntry.java
 *
 * Created on den 28 aug 2002, 10:02
 */

package se.anatom.ejbca.log;

import java.util.Date;

/**
 *  This is a  class containing information about one log event in the database. Used mainly during database queries by the web interface.
 *
 * @author  TomSelleck
 */
public class LogEntry implements java.io.Serializable {
  
    // Public constants
    
    /*Possible log events, all information events should have an id below 1000 and all error events should have a id above 1000 */
    // Information events. Important all id:s should map to the array EVENTNAMES_INFO.
    public static final int EVENT_INFO_UNKNOWN                        = 0;    
    public static final int EVENT_INFO_ADDEDENDENTITY                 = 1;
    public static final int EVENT_INFO_CHANGEDENDENTITY               = 2;  
    public static final int EVENT_INFO_REVOKEDENDENTITY               = 3;    
    public static final int EVENT_INFO_REVOKEDCERT                    = 4;      
    public static final int EVENT_INFO_DELETEDENDENTITY               = 5;
    public static final int EVENT_INFO_EDITSYSTEMCONFIGURATION        = 6;  
    public static final int EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES  = 7;
    public static final int EVENT_INFO_EDITLOGCONFIGURATION           = 8;
    public static final int EVENT_INFO_ADMINISTRATORPREFERENCECHANGED = 9;
    public static final int EVENT_INFO_ENDENTITYPROFILE               = 10;
    public static final int EVENT_INFO_USERAUTHENTICATION             = 11;
    public static final int EVENT_INFO_STORECERTIFICATE               = 12;
    public static final int EVENT_INFO_STORECRL                       = 13;
    public static final int EVENT_INFO_GETLASTCRL                     = 14;
    public static final int EVENT_INFO_CERTPROFILE                    = 15;
    public static final int EVENT_INFO_DATABASE                       = 16;
    public static final int EVENT_INFO_CREATECERTIFICATE              = 17;
    public static final int EVENT_INFO_CREATECRL                      = 18;
    public static final int EVENT_INFO_ADMINISTRATORLOGGEDIN          = 19;
    public static final int EVENT_INFO_AUTHORIZEDTORESOURCE           = 20;
    public static final int EVENT_INFO_PUBLICWEBUSERCONNECTED         = 21;   
    public static final int EVENT_INFO_HARDTOKEN_USERDATASENT         = 22; 
    public static final int EVENT_INFO_HARDTOKENGENERATED             = 23; 
    public static final int EVENT_INFO_HARDTOKENDATA                  = 24;   
    public static final int EVENT_INFO_HARDTOKENISSUERDATA            = 25;
    public static final int EVENT_INFO_HARDTOKENCERTIFICATEMAP        = 26;   
    public static final int EVENT_INFO_KEYRECOVERY                    = 27;  
    public static final int EVENT_INFO_NOTIFICATION                   = 28;
    public static final int EVENT_INFO_HARDTOKENVIEWED                = 29; 
    public static final int EVENT_INFO_CACREATED                      = 30;
    public static final int EVENT_INFO_CAEDITED                       = 31;
    public static final int EVENT_INFO_CAREVOKED                      = 32;
    
    
    // Error events. Important all id:s should map to the array EVENTNAMES_ERROR - EVENT_ERROR_BOUNDRARY.
    public static final int EVENT_ERROR_UNKNOWN                        = 1000;      
    public static final int EVENT_ERROR_ADDEDENDENTITY                 = 1001;
    public static final int EVENT_ERROR_CHANGEDENDENTITY               = 1002;  
    public static final int EVENT_ERROR_REVOKEDENDENTITY               = 1003;    
    public static final int EVENT_ERROR_REVOKEDCERT                    = 1004;  
    public static final int EVENT_ERROR_DELETEENDENTITY                = 1005;
    public static final int EVENT_ERROR_EDITSYSTEMCONFIGURATION        = 1006;      
    public static final int EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES  = 1007;
    public static final int EVENT_ERROR_EDITLOGCONFIGURATION           = 1008;    
    public static final int EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED = 1009;
    public static final int EVENT_ERROR_ENDENTITYPROFILE               = 1010;
    public static final int EVENT_ERROR_USERAUTHENTICATION             = 1011;
    public static final int EVENT_ERROR_STORECERTIFICATE               = 1012;
    public static final int EVENT_ERROR_STORECRL                       = 1013;
    public static final int EVENT_ERROR_GETLASTCRL                     = 1014;
    public static final int EVENT_ERROR_CERTPROFILE                    = 1015;
    public static final int EVENT_ERROR_DATABASE                       = 1016;
    public static final int EVENT_ERROR_CREATECERTIFICATE              = 1017;
    public static final int EVENT_ERROR_CREATECRL                      = 1018; 
    public static final int EVENT_ERROR_ADMINISTRATORLOGGEDIN          = 1019;
    public static final int EVENT_ERROR_NOTAUTHORIZEDTORESOURCE        = 1020;
    public static final int EVENT_ERROR_PUBLICWEBUSERCONNECTED         = 1021;      
    public static final int EVENT_ERROR_HARDTOKEN_USERDATASENT         = 1022; 
    public static final int EVENT_ERROR_HARDTOKENGENERATED             = 1023; 
    public static final int EVENT_ERROR_HARDTOKENDATA                  = 1024;   
    public static final int EVENT_ERROR_HARDTOKENISSUERDATA            = 1025;
    public static final int EVENT_ERROR_HARDTOKENCERTIFICATEMAP        = 1026;      
    public static final int EVENT_ERROR_KEYRECOVERY                    = 1027;    
    public static final int EVENT_ERROR_NOTIFICATION                   = 1028;  
    public static final int EVENT_ERROR_HARDTOKENVIEWED                = 1029;    
    public static final int EVENT_ERROR_CACREATED                      = 1030;
    public static final int EVENT_ERROR_CAEDITED                       = 1031;
    public static final int EVENT_ERROR_CAREVOKED                      = 1032;
    
    
    // Indicates the module using the logsession bean.
    public static final int MODULE_CA                  = 0;
    public static final int MODULE_RA                  = 1;
    public static final int MODULE_LOG                 = 2;    
    public static final int MODULE_PUBLICWEB           = 3;
    public static final int MODULE_ADMINWEB            = 4;
    public static final int MODULE_HARDTOKEN           = 5;
    public static final int MODULE_KEYRECOVERY         = 6;    
    public static final int MODULE_AUTHORIZATION       = 7;
        
    public static final int EVENT_ERROR_BOUNDRARY                = 1000;
    
    // Id -> String maps
    public static final String[] EVENTNAMES_INFO = {"EVENT_INFO_UNKNOWN", "EVENT_INFO_ADDEDENDENTITY", "EVENT_INFO_CHANGEDENDENTITY" , "EVENT_INFO_REVOKEDENDENTITY", "EVENT_INFO_REVOKEDCERT", 
                                                    "EVENT_INFO_DELETEDENDENTITY", "EVENT_INFO_EDITSYSTEMCONFIGURATION", "EVENT_INFO_EDITEDADMINISTRATORPRIVILEGES",
                                                    "EVENT_INFO_EDITLOGCONFIGURATION", "EVENT_INFO_ADMINISTRATORPREFERENCECHANGED", "EVENT_INFO_ENDENTITYPROFILE", "EVENT_INFO_USERAUTHENTICATION",
                                                    "EVENT_INFO_STORECERTIFICATE", "EVENT_INFO_STORECRL", "EVENT_INFO_GETLASTCRL", "EVENT_INFO_CERTPROFILE", "EVENT_INFO_DATABASE",
                                                    "EVENT_INFO_CREATECERTIFICATE", "EVENT_INFO_CREATECRL", "EVENT_INFO_ADMINISTRATORLOGGEDIN", "EVENT_INFO_AUTHORIZEDTORESOURCE", 
                                                    "EVENT_INFO_PUBLICWEBUSERCONNECTED", "EVENT_INFO_HARDTOKEN_USERDATASENT","EVENT_INFO_HARDTOKENGENERATED","EVENT_INFO_HARDTOKENDATA",
                                                    "EVENT_INFO_HARDTOKENISSUERDATA", "EVENT_INFO_HARDTOKENCERTIFICATEMAP", "EVENT_INFO_KEYRECOVERY", "EVENT_INFO_NOTIFICATION",
                                                    "EVENT_INFO_HARDTOKENVIEWED", "EVENT_INFO_CACREATED", "EVENT_INFO_CAEDITED", "EVENT_INFO_CAREVOKED" };   
    
                                                                                                         
    public static final String[] EVENTNAMES_ERROR = {"EVENT_ERROR_UNKNOWN", "EVENT_ERROR_ADDEDENDENTITY", "EVENT_ERROR_CHANGEDENDENTITY" , "EVENT_ERROR_REVOKEDENDENTITY", "EVENT_ERROR_REVOKEDCERT",
                                                     "EVENT_ERROR_DELETEENDENTITY", "EVENT_ERROR_EDITSYSTEMCONFIGURATION", "EVENT_ERROR_EDITEDADMINISTRATORPRIVILEGES",
                                                     "EVENT_ERROR_EDITLOGCONFIGURATION", "EVENT_ERROR_ADMINISTRATORPREFERENCECHANGED", "EVENT_ERROR_ENDENTITYPROFILE", "EVENT_ERROR_USERAUTHENTICATION",
                                                     "EVENT_ERROR_STORECERTIFICATE", "EVENT_ERROR_STORECRL", "EVENT_ERROR_GETLASTCRL", "EVENT_ERROR_CERTPROFILE", "EVENT_ERROR_DATABASE",
                                                     "EVENT_ERROR_CREATECERTIFICATE", "EVENT_ERROR_CREATECRL" ,"EVENT_ERROR_ADMINISTRATORLOGGEDIN", "EVENT_ERROR_NOTAUTHORIZEDTORESOURCE",
                                                     "EVENT_ERROR_PUBLICWEBUSERCONNECTED","EVENT_ERROR_HARDTOKEN_USERDATASENT","EVENT_ERROR_HARDTOKENGENERATED","EVENT_ERROR_HARDTOKENDATA",
                                                     "EVENT_ERROR_HARDTOKENISSUERDATA", "EVENT_ERROR_HARDTOKENCERTIFICATEMAP", "EVENT_ERROR_KEYRECOVERY", "EVENT_ERROR_NOTIFICATION",
                                                     "EVENT_ERROR_HARDTOKENVIEWED", "EVENT_ERROR_CACREATED", "EVENT_ERROR_CAEDITED", "EVENT_ERROR_CAREVOKED"};    
                                                     
    public static final String[] MODULETEXTS    = {"CA", "RA", "LOG", "PUBLICWEB", "ADMINWEB", "HARDTOKEN", "KEYRECOVERY", "AUTHORIZATION"};                                                     
    
   /** 
    * Function used by EJBCA to log information.
    *
    * @param admintype is pricipally the type of data stored in the admindata field, should be one of se.anatom.ejbca.log.Admin.TYPE_ constants.
    * @param admindata is the data identifying the administrator, should be certificate snr or ip-address when no certificate could be retrieved.
    * @param module indicates from which module the event was logged. i.e RA, CA ....
    * @param time the time the event occured.
    * @param username the name of the user involved or null if no user is involved.
    * @param certificate the certificate involved in the event or null if no certificate is involved.
    * @param event id of the event, should be one of the se.anatom.ejbca.log.LogEntry.EVENT_ constants.
    * @param comment comment of the event.
    */    
    
    public LogEntry(int admintype, String admindata, int caid, int module, Date time, String username, String certificatesnr, int event, String comment){
       this.admintype=admintype;
       this.admindata=admindata;
       this.caid=caid;
       this.module=module;
       this.time=time;
       this.username=username;
       this.certificatesnr=certificatesnr;
       this.event=event;
       this.comment=comment;
    }
    
    // Public methods
    
    /**
     * Method used to map between event id and a string representation of event
     *
     * @return a string representation of the event.
     */
    public String getEventName(){
      if(this.event >= EVENT_ERROR_BOUNDRARY)
        return EVENTNAMES_ERROR[this.event - EVENT_ERROR_BOUNDRARY];
      else
        return EVENTNAMES_INFO[this.event];                  
    }
    
    
    public int getAdminType(){
      return this.admintype;   
    }
    
    public String getAdminData(){
      return this.admindata;   
    }
    
    public int getCAId(){
      return this.caid;   
    }
    
    public int getModule(){
      return this.module;    
    }

    public Date getTime(){
      return this.time;   
    }
    
    public String getUsername(){
      return this.username;   
    }    
 
    public String getCertificateSNR(){
      return this.certificatesnr;   
    }    
    
    public int getEvent(){
      return this.event;   
    }
  
    public String getComment(){
      return this.comment;   
    } 
       
    // Private methods 
    
    // Private fields
    private    int    admintype;
    private    String admindata;
    private    int    caid;
    private    int    module;
    private    Date   time;
    private    String username;
    private    String certificatesnr;
    private    int    event;
    private    String comment;
    
}
