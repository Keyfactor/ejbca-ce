package se.anatom.ejbca.ra;

import se.anatom.ejbca.util.UpgradeableDataHashMap;

/**
 *  This is a  class containing global configuration parameters.
 *
 * @version $Id: GlobalConfiguration.java,v 1.7 2003-02-06 15:35:53 herrvendil Exp $
 */
public class GlobalConfiguration extends UpgradeableDataHashMap implements java.io.Serializable {
  
    // Default Values
    public static final float LATEST_VERSION = 1;
    
       
    // Entries to choose from in userpreference part, defines the size of data to be displayed on one page.                                                  
    private final  String[] DEFAULTPOSSIBLEENTRIESPERPAGE = {"10" , "25" , "50" , "100"};    
    // Entries to choose from in view log part, defines the size of data to be displayed on one page.                                                  
    private final  String[] DEFAULTPOSSIBLELOGENTRIESPERPAGE = {"10" , "25" , "50" , "100", "200", "400"};        
    
    // Rules available by default i authorization module.
    private  final  String[] DEFAULT_AVAILABLE_RULES = { "/", "/ca_functionallity", "/ca_functionallity/basic_functions",
                                                       "/ca_functionallity/view_certificate", "/ca_functionallity/create_crl",
                                                       "/ca_functionallity/edit_certificate_profiles", "/ra_functionallity/edit_end_entity_profiles",
                                                       "/ra_functionallity", "/ra_functionallity/edit_end_entity_profiles", "/ra_functionallity/view_end_entity", 
                                                       "/ra_functionallity/create_end_entity", "/ra_functionallity/edit_end_entity", "/ra_functionallity/delete_end_entity",
                                                       "/ra_functionallity/revoke_end_entity","/ra_functionallity/view_end_entity_history","/log_functionallity",
                                                       "/log_functionallity/view_log","/log_functionallity/view_log/log_entries","/log_functionallity/view_log/ca_entries","/log_functionallity/view_log/ra_entries",
                                                       "/log_functionallity/edit_log_configuration","/log_functionallity/view_log/adminweb_entries","/log_functionallity/view_log/publicweb_entries",
                                                       "/system_functionallity","/system_functionallity/edit_system_configuration", "/system_functionallity/edit_administrator_privileges",
                                                       "/system_functionallity/edit_administrator_privileges/edit_available_accessrules"};
                                                       
    public static final String[] LOGMODULERESOURCES = { "/log_functionallity/view_log/ca_entries","/log_functionallity/view_log/ra_entries","/log_functionallity/view_log/log_entries",
                                                        "/log_functionallity/view_log/publicweb_entries","/log_functionallity/view_log/adminweb_entries","/log_functionallity/view_log/hardtoken_entries" };                                                   
                                                    
    // Available end entity profile authorization rules.                                                   
    public static final String VIEW_RIGHTS = "/view_end_entity";
    public static final String EDIT_RIGHTS = "/edit_end_entity";
    public static final String CREATE_RIGHTS = "/create_end_entity";
    public static final String DELETE_RIGHTS = "/delete_end_entity";
    public static final String REVOKE_RIGHTS = "/revoke_end_entity";
    public static final String HISTORY_RIGHTS = "/view_end_entity_history";    
                                                       
    // Endings to add to profile authorizxation.                                                   
    public static final String[]  ENDENTITYPROFILE_ENDINGS        = {VIEW_RIGHTS,EDIT_RIGHTS,CREATE_RIGHTS,DELETE_RIGHTS,REVOKE_RIGHTS,HISTORY_RIGHTS};
    
    // Name of end entity profile prefix directory in authorization module.
    public static final String    ENDENTITYPROFILEPREFIX          = "/endentityprofilesrules/";
    
    // Hard Token specific resources used in authorization module.
    public static final String[] HARDTOKENRESOURCES               ={"/hardtoken_functionallity/edit_hardtoken_issuers"};
    public static final String   HARDTOKEN_RA_ENDING              ="/view_hardtoken";
        
    // Hard Token specific resource used in authorization module.    
    public static final String  KEYRECOVERYRESOURCE                ="/keyrecovery";
   
    // Path added to baseurl used as default vaule in CRLDistributionPointURI field in Certificate Type definitions.
    private final  String   DEFAULTCRLDISTURIPATH  = "ejbca/webdist/certdist?cmd=crl";
        
    // Default name of headbanner in web interface.
    private final  String   DEFAULTHEADBANNER             = "head_banner.jsp";
    // Default name of footbanner page in web interface.
    private final  String   DEFAULTFOOTBANNER             = "foot_banner.jsp";
    
    // Title of ra admin web interface.
    private final  String   DEFAULTEJBCATITLE             = "Enterprise Java Bean Certificate Authority";
    
    // Language codes. Observe the order is important
    public static final  int      EN                 = 0; 
    public static final  int      SE                 = 1;
    
    // Public constants.
    public static final  String HEADERFRAME         = "topFrame";  // Name of header browser frame
    public static final  String MENUFRAME           = "leftFrame"; // Name of menu browser frame
    public static final  String MAINFRAME           = "mainFrame"; // Name of main browser frame  
    

    
    /** Creates a new instance of Globaldatauration */
    public GlobalConfiguration()  {    
       super(); 
       
       setEjbcaTitle(DEFAULTEJBCATITLE);                       
       setEnableEndEntityProfileLimitations(false);
       setEnableAuthenticatedUsersOnly(false);
       setEnableKeyRecovery(false);
       setIssueHardwareTokens(false);
    }
    
    /** Initializes a new global datauration with data used in ra web interface. */
    public void initialize(String baseurl, String adminpath, String availablelanguages, String availablethemes, 
                           String publicport, String privateport, String publicprotocol, String privateprotocol){                       
       String tempbaseurl            = baseurl;
       String tempadminpath           = adminpath.trim();
       
       if(!tempbaseurl.endsWith("/")){
         tempbaseurl = tempbaseurl + "/";   
       }
       if(tempadminpath == null)
         tempadminpath = "";
       if(!tempadminpath.endsWith("/") && !tempadminpath.equals("")){
         tempadminpath = tempadminpath + "/";   // Add ending '/'
       }         
       if(tempadminpath.startsWith("/")){
         tempadminpath =tempadminpath.substring(1);   // Remove starting '/'
       }   
       
       String[] tempdefaultdirs = new String[DEFAULT_AVAILABLE_RULES.length+2];
       tempdefaultdirs[0] = "/";
       tempdefaultdirs[1] = "/" +  tempadminpath;     
       for(int i=2;i < tempdefaultdirs.length; i++){
          tempdefaultdirs[i] =  "/" + tempadminpath + DEFAULT_AVAILABLE_RULES[i-2];  
       }           
       
       setBaseUrl(tempbaseurl);
       data.put(ADMINPATH,tempadminpath);
       data.put(AVAILABLELANGUAGES,availablelanguages.trim());
       data.put(AVAILABLETHEMES,availablethemes.trim());
       data.put(PUBLICPORT,publicport.trim());  
       data.put(PRIVATEPORT,privateport.trim());     
       data.put(PUBLICPROTOCOL,publicprotocol.trim());  
       data.put(PRIVATEPROTOCOL,privateprotocol.trim());
      
       data.put(AUTHORIZATION_PATH,tempadminpath+"administratorprivileges");
       data.put(BANNERS_PATH,"banners");
       data.put(CA_PATH, tempadminpath+"ca");
       data.put(CONFIG_PATH,tempadminpath+"sysconfig");
       data.put(HELP_PATH,"help");
       data.put(IMAGES_PATH,"images");
       data.put(LANGUAGE_PATH,"languages");
       data.put(LOG_PATH,tempadminpath+"log");
       data.put(RA_PATH,tempadminpath+"ra");
       data.put(THEME_PATH,"themes");
       data.put(HARDTOKEN_PATH,tempadminpath+"hardtoken");
       
       data.put(LANGUAGEFILENAME,"languagefile");
       data.put(MAINFILENAME,"main.jsp");
       data.put(INDEXFILENAME,"index.jsp");
       data.put(MENUFILENAME,"adminmenu.jsp");
       data.put(ERRORPAGE,"errorpage.jsp");
           
       setHeadBanner(DEFAULTHEADBANNER);
       setFootBanner(DEFAULTFOOTBANNER);
        
    }
    
    /** Checks if global datauration have been initialized. */
    public boolean isInitialized(){
      return data.get(BASEURL)!=null;   
    }
       
    public   String getBaseUrl() {return (String) data.get(BASEURL);}
    public   void setBaseUrl(String burl){
      // Add trailing '/' if it doesn't exists.  
      if(!burl.endsWith("/")){
        data.put(BASEURL,burl + "/");    
      }
      else{
        data.put(BASEURL,burl);    
      }
    }
        
    public String getAdminWebPath(){return (String) data.get(ADMINPATH);}
    
    public String getStandardCRLDistributionPointURI(){ 
        String retval = (String) data.get(BASEURL);
        retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));        
        retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval+= DEFAULTCRLDISTURIPATH;
        return retval;
    }
    
    /** Returns the default available resources in the authorization module. */
    public String[] getDefaultAvailableResources(){return DEFAULT_AVAILABLE_RULES;}
        
     /** Checks the themes paht for css files and returns an array of filenames
     *  without the ".css" ending. */    
    public   String[] getAvailableThemes() {
       String[] availablethemes;
       availablethemes =  getAvailableThenesAsString().split(",");
       if(availablethemes != null){
         for(int i = 0; i <  availablethemes.length; i++){
           availablethemes[i] = availablethemes[i].trim();   
           if(availablethemes[i].endsWith(".css")){
             availablethemes[i] = availablethemes[i].substring(0,availablethemes[i].length()-4);    
           }
         }
       }
       return availablethemes;
    }
    
    /** Returns the default avaiable theme used by administrator preferences. */
    public String getDefaultAvailableTheme(){
      return getAvailableThemes()[0];   
    }
     
    // Methods for manipulating the headbanner filename. 
    public   String getHeadBanner() {return (String) data.get(HEADBANNER);}
    public   String getHeadBannerFilename(){
      String returnval = (String) data.get(HEADBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public   void setHeadBanner(String head){
      data.put(HEADBANNER, ((String) data.get(ADMINPATH)) + ((String) data.get(BANNERS_PATH)) + "/" + head);
    }
    
    
    // Methods for manipulating the headbanner filename.     
    public   String getFootBanner() {return (String) data.get(FOOTBANNER);} 
    public   String getFootBannerFilename(){
      String returnval = (String) data.get(FOOTBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public   void setFootBanner(String foot){
      data.put(FOOTBANNER,  "/" + ((String) data.get(BANNERS_PATH)) + "/" +foot);
    }
    
    // Methods for manipulating the title.     
    public   String getEjbcaTitle() {return (String) data.get(TITLE);}
    public   void setEjbcaTitle(String ejbcatitle) {data.put(TITLE,ejbcatitle);}

       
    public   String getAuthorizationPath() {return (String) data.get(AUTHORIZATION_PATH);}  
    public   String getBannersPath() {return (String) data.get(BANNERS_PATH);}
    public   String getCaPath() {return (String) data.get(CA_PATH);}
    public   String getConfigPath() {return (String) data.get(CONFIG_PATH);}
    public   String getHelpPath() {return (String) data.get(HELP_PATH);}
    public   String getImagesPath() {return (String) data.get(IMAGES_PATH);}
    public   String getLanguagePath() {return (String) data.get(LANGUAGE_PATH);}       
    public   String getLogPath() {return (String) data.get(LOG_PATH);}        
    public   String getRaPath() {return (String) data.get(RA_PATH);}
    public   String getThemePath() {return (String) data.get(THEME_PATH);}
    public   String getHardTokenPath() {return (String) data.get(HARDTOKEN_PATH);}
            
    public   String getLanguageFilename(){return (String) data.get(LANGUAGEFILENAME);}
    public   String getMainFilename(){return (String) data.get(MAINFILENAME);}   
    public   String getIndexFilename(){return (String) data.get(INDEXFILENAME);}   
    public   String getMenuFilename(){return (String) data.get(MENUFILENAME);}   
    public   String getErrorPage(){return (String) data.get(ERRORPAGE);}   
    
    public   String[] getPossibleEntiresPerPage(){return DEFAULTPOSSIBLEENTRIESPERPAGE;}      
    public   String[] getPossibleLogEntiresPerPage(){return DEFAULTPOSSIBLELOGENTRIESPERPAGE;}
    
    public   String getAvailableLanguagesAsString(){return (String) data.get(AVAILABLELANGUAGES);} 
    public   String getAvailableThenesAsString(){return (String) data.get(AVAILABLETHEMES);}  
    
    public   boolean getEnableEndEntityProfileLimitations(){return ((Boolean) data.get(ENABLEEEPROFILELIMITATIONS)).booleanValue();}
    public   void    setEnableEndEntityProfileLimitations(boolean value){ data.put(ENABLEEEPROFILELIMITATIONS,new Boolean(value));}
 
    public   boolean getEnableAuthenticatedUsersOnly(){return ((Boolean) data.get(ENABLEAUTHENTICATEDUSERSONLY)).booleanValue();}
    public   void    setEnableAuthenticatedUsersOnly(boolean value){ data.put(ENABLEAUTHENTICATEDUSERSONLY,new Boolean(value));}    
 
    public   boolean getEnableKeyRecovery(){return ((Boolean) data.get(ENABLEKEYRECOVERY)).booleanValue();}
    public   void    setEnableKeyRecovery(boolean value){ data.put(ENABLEKEYRECOVERY,new Boolean(value));}    
    
    public   boolean getIssueHardwareTokens(){return ((Boolean) data.get(ISSUEHARDWARETOKENS)).booleanValue();}
    public   void    setIssueHardwareTokens(boolean value){ data.put(ISSUEHARDWARETOKENS,new Boolean(value));} 
    
    
    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;  
    }
    
    /** Implemtation of UpgradableDataHashMap function upgrade. */    
    
    public void upgrade(){
      if(LATEST_VERSION != getVersion()){
        // New version of the class, upgrade  
        if(data.get(HARDTOKEN_PATH) == null){
          data.put(HARDTOKEN_PATH, ((String) data.get(ADMINPATH) + "hardtoken"));  
        }
          
        data.put(VERSION, new Float(LATEST_VERSION));  
       
               
      }  
    }
    
    // Private fields.

    // Private constants
    private final   String BASEURL            = "baseurl";
    private final   String ADMINPATH          = "raadminpath";
    private final   String AVAILABLELANGUAGES = "availablelanguages";
    private final   String AVAILABLETHEMES    = "availablethemes";
    private final   String PUBLICPORT         = "publicport";
    private final   String PRIVATEPORT        = "privateport";
    private final   String PUBLICPROTOCOL     = "publicprotocol";
    private final   String PRIVATEPROTOCOL    = "privateprotocol";    
   
    
      // Title
    private final   String TITLE              = "title";      
      // Banner files.
    private final   String HEADBANNER         = "headbanner";  
    private final   String FOOTBANNER         = "footbanner";    
      // Other configuration.
    private final   String ENABLEEEPROFILELIMITATIONS   = "endentityprofilelimitations"; 
    private final   String ENABLEAUTHENTICATEDUSERSONLY = "authenticatedusersonly"; 
    private final   String ENABLEKEYRECOVERY            = "enablekeyrecovery";
    private final   String ISSUEHARDWARETOKENS          = "issuehardwaretokens";
      // Paths
    private final   String AUTHORIZATION_PATH  = "authorization_path";   
    private final   String BANNERS_PATH        = "banners_path";
    private final   String CA_PATH             = "ca_path";
    private final   String CONFIG_PATH         = "data_path";   
    private final   String HELP_PATH           = "help_path"; 
    private final   String IMAGES_PATH         = "images_path";
    private final   String LANGUAGE_PATH       = "language_path";
    private final   String LOG_PATH            = "log_path"; 
    private final   String RA_PATH             = "ra_path";
    private final   String THEME_PATH          = "theme_path"; 
    private final   String HARDTOKEN_PATH      = "hardtoken_path";
    
    private final   String LANGUAGEFILENAME    =  "languagefilename"; 
    private final   String MAINFILENAME        =  "mainfilename"; 
    private final   String INDEXFILENAME       =  "indexfilename"; 
    private final   String MENUFILENAME        =  "menufilename"; 
    private final   String ERRORPAGE           =  "errorpage";  
              
}
