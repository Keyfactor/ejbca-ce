/*
 * GlobalConfiguration.java
 *
 * Created on den 28 mars 2002, 10:02
 */

package se.anatom.ejbca.ra;

import java.io.IOException;
import java.util.HashMap;
import javax.naming.InitialContext;
import javax.naming.Context;

import se.anatom.ejbca.ra.raadmin.UserPreference;

/**
 *  This is a  class containing global configuration parameters and default
 *  user preferences.
 *
 * @author  Philip Vendil
 */
public class GlobalConfiguration implements java.io.Serializable {
  
    // Default Values
    // Entries to choose from in userpreference part, defines the size of data to be displayed on one page.                                                  
    private final  String[] POSSIBLEENTRIESPERPAGE = {"10" , "25" , "50" , "100"};    
    
    // Directories made open to all ra administrators, but client certificate is still needed.
    private final  String[] OPENDIRECTORIES        = {"/raadmin/", "/raadmin/banners","/raadmin/images","/raadmin/help",
                                                      "/raadmin/themes","/raadmin/languages"};    
    // Rules available by default i authorization module.
    private final  String[]  DEFAULT_AVAILABLE_RULES = {"/", "/raadmin/", "/raadmin/authorization", "/raadmin/authorization/availablerules", 
                                                       "/raadmin/ca", "/raadmin/ca/createcrl", "/raadmin/ca/getcrl", "/raadmin/config", 
                                                       "/raadmin/ra", "/raadmin/ra/editprofiles"};
                                                      
    // Endings to add to profile authorizxation.                                                   
    private final String[]  PROFILE_ENDINGS        = {"/view", "/create", "/edit", "/delete", "/revoke","/history"};  
    // Name of profile prefix directory in authorization module.
    private final String    PROFILEPREFIX          = "/profiles";
   
    // Name of headbanner in web interface.
    private final  String   HEADBANNER             = "head_banner.jsp";
    // Name of footbanner page in web interface.
    private final  String   FOOTBANNER             = "foot_banner.jsp";
    
    // Title of ra admin web interface.
    private final  String   EJBCATITLE             = "Enterprise Java Bean Certificate Authority";
    
    // Language codes. Observe the order is important
    public final  int      EN                 = 0; 
    public final  int      SE                 = 1;
    
    // Public constants.
    public final  String HEADERFRAME         = "topFrame";  // Name of header browser frame
    public final  String MENUFRAME           = "leftFrame"; // Name of menu browser frame
    public final  String MAINFRAME           = "mainFrame"; // Name of main browser frame  
    

    
    /** Creates a new instance of GlobalConfiguration */
    public GlobalConfiguration()  {    
       defaultuserpreference = new UserPreference();
       config = new HashMap();
 
       setEjbcaTitle(EJBCATITLE);       
       config.put(P_POSSIBLEENTRIESPERPAGE,POSSIBLEENTRIESPERPAGE);       
       config.put(P_PROFILE_ENDINGS,PROFILE_ENDINGS);
       config.put(P_PROFILEPREFIX,PROFILEPREFIX);
       
       config.put(P_OPENDIRECTORIES, OPENDIRECTORIES);
       config.put(P_DEFAULT_AVAILABLE_RULES, DEFAULT_AVAILABLE_RULES);
    }
    
    /** Initializes a new global configuration with data used in ra web interface. */
    public void initialize(String baseurl, String raadminpath, String availablelanguages, String availablethemes){
       String tempbaseurl = baseurl;
       String tempraadminpath =  raadminpath.trim();
       String tempavailablelanguages = availablelanguages.trim();
       String tempavailablethemes = availablethemes.trim();        
        
       if(!tempbaseurl.endsWith("/")){
         tempbaseurl = tempbaseurl + "/";   // Remove ending '/'
       }
       if(tempraadminpath == null)
         tempraadminpath = "";
       if(!tempraadminpath.endsWith("/") && !tempraadminpath.equals("")){
         tempraadminpath = tempraadminpath + "/";   // Add ending '/'
       }         
       if(tempraadminpath.startsWith("/")){
         tempraadminpath =tempraadminpath.substring(1);   // Remove starting '/'
       }   
       
       
       setBaseUrl(tempbaseurl);
       config.put(P_RAADMINPATH,tempraadminpath);
       config.put(P_AVAILABLELANGUAGES,tempavailablelanguages);
       config.put(P_AVAILABLETHEMES,tempavailablethemes);
      
       config.put(P_AUTHORIZATION_PATH,tempraadminpath+"authorization");
       config.put(P_BANNERS_PATH,"banners");
       config.put(P_CA_PATH, tempraadminpath+"ca");
       config.put(P_CONFIG_PATH,tempraadminpath+"config");
       config.put(P_HELP_PATH,"help");
       config.put(P_IMAGES_PATH,"images");
       config.put(P_LANGUAGE_PATH,"languages");
       config.put(P_LOG_PATH,tempraadminpath+"log");
       config.put(P_RA_PATH,tempraadminpath+"ra");
       config.put(P_THEME_PATH,"themes");
       
       config.put(P_LANGUAGEFILENAME,"languagefile");
       config.put(P_MAINFILENAME,"main.jsp");
       config.put(P_INDEXFILENAME,"index.jsp");
       config.put(P_MENUFILENAME,"ejbcamenu.jsp");
       config.put(P_ERRORPAGE,"errorpage.jsp");
           
       defaultuserpreference.setTheme(getAvailableThemes()[0]);    
       setHeadBanner(HEADBANNER);
       setFootBanner(FOOTBANNER);
        
    }
    
    /** Checks if global configuration have been initialized. */
    public boolean isInitialized(){
      return config.get(P_BASEURL)!=null;   
    }
    
    // Configurable fields.    
    public   String getBaseUrl() {return (String) config.get(P_BASEURL);}
    public   void setBaseUrl(String burl){
      // Add trailing '/' if it doesn't exists.  
      if(!burl.endsWith("/")){
        config.put(P_BASEURL,burl + "/");    
      }
      else{
        config.put(P_BASEURL,burl);    
      }
    }
    
    
    public   String getRaAdminPath(){return (String) config.get(P_RAADMINPATH);}

    public   String[] getOpenDirectories() {return (String[]) config.get(P_OPENDIRECTORIES);} 
    // Returns all opendirectories as a comma-separated string.
    public   String getOpenDirectoriesAsString(){
      String[] opendirectories = (String[]) config.get(P_OPENDIRECTORIES); 
      String returnvalue="";
      for(int i=0; i < opendirectories.length -1; i++){
         returnvalue += opendirectories[i] + ", ";   
      }
      returnvalue+= opendirectories[opendirectories.length-1];
      
      return returnvalue;
    }
    
    /** Returns the default available directories in the authorization module. */
    public String[] getDefaultAvailableDirectories(){return (String[]) config.get(P_DEFAULT_AVAILABLE_RULES);}
    
    /** Returns authorization rules applied to profile groups */
    public String[] getProfileEndings(){return (String[]) config.get(P_PROFILE_ENDINGS);}
    
    /** Gives the directory profilegroups are placed in auhtorization module. */
    public String getProfilePrefix(){return (String) config.get(P_PROFILEPREFIX);} 
    
    /** The opendirectories parameter is a comma separated string containing the 
        open directories*/
    public   void setOpenDirectories(String opendirs){
      opendirs=opendirs.trim();  
      if(opendirs.endsWith(",")){
        opendirs=opendirs.substring(0,opendirs.length()-1);   
      }
      String[] dirs = opendirs.split(",");
    
      for(int i=0; i < dirs.length; i++){
         dirs[i]=dirs[i].trim();   
         // Add a heading "/" if it doesn't exists. 
         if(!dirs[i].startsWith("/")){
           dirs[i]= "/" +dirs[i];   
         }
      }
      
      config.put(P_OPENDIRECTORIES,dirs);
    }
        
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
    
     /** Special function used in confuration part that doesn't return a copy of the object. */
     public   UserPreference getRealDefaultPreference(){  
       return defaultuserpreference;
    }   
    
    public   UserPreference getDefaultPreference(){
       UserPreference returnvalue=null;
       try{
         returnvalue = (UserPreference) defaultuserpreference.clone();
       }catch( Exception e){   
       }
       return returnvalue;
    }
    

    
    public   String getHeadBanner() {return (String) config.get(P_HEADBANNER);}
    public   String getHeadBannerFilename(){
      String returnval = (String) config.get(P_HEADBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public   void setHeadBanner(String head){config.put(P_HEADBANNER, ((String) config.get(P_RAADMINPATH)) +
                                                             ((String) config.get(P_BANNERS_PATH)) + "/" + head);}
    public   String getFootBanner() {return (String) config.get(P_FOOTBANNER);} 
    public   String getFootBannerFilename(){
      String returnval = (String) config.get(P_FOOTBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public   void setFootBanner(String foot){config.put(P_FOOTBANNER,  "/" + ((String) config.get(P_BANNERS_PATH)) + "/" +foot);}
    
    public   String getEjbcaTitle() {return (String) config.get(P_TITLE);}
    public   void setEjbcaTitle(String ejbcatitle) {config.put(P_TITLE,ejbcatitle);}
    //   fields
       
    public   String getAuthorizationPath() {return (String) config.get(P_AUTHORIZATION_PATH);}  
    public   String getBannersPath() {return (String) config.get(P_BANNERS_PATH);}
    public   String getCaPath() {return (String) config.get(P_CA_PATH);}
    public   String getConfigPath() {return (String) config.get(P_CONFIG_PATH);}
    public   String getHelpPath() {return (String) config.get(P_HELP_PATH);}
    public   String getImagesPath() {return (String) config.get(P_IMAGES_PATH);}
    public   String getLanguagePath() {return (String) config.get(P_LANGUAGE_PATH);}       
    public   String getLogPath() {return (String) config.get(P_LOG_PATH);}        
    public   String getRaPath() {return (String) config.get(P_RA_PATH);}
    public   String getThemePath() {return (String) config.get(P_THEME_PATH);}
            
    public   String getLanguageFilename(){return (String) config.get(P_LANGUAGEFILENAME);}
    public   String getMainFilename(){return (String) config.get(P_MAINFILENAME);}   
    public   String getIndexFilename(){return (String) config.get(P_INDEXFILENAME);}   
    public   String getMenuFilename(){return (String) config.get(P_MENUFILENAME);}   
    public   String getErrorPage(){return (String) config.get(P_ERRORPAGE);}   
    
    public   String[] getPossibleEntiresPerPage(){return (String[]) config.get(P_POSSIBLEENTRIESPERPAGE);}      

    public   String getAvailableLanguagesAsString(){return (String) config.get(P_AVAILABLELANGUAGES);} 
    public   String getAvailableThenesAsString(){return (String) config.get(P_AVAILABLETHEMES);}         
    
    // Private fields.
    
    // Private constants
      // Basic configuration
    private final   String P_BASEURL            = "baseurl";
    private final   String P_RAADMINPATH        = "raadminpath";
    private final   String P_AVAILABLELANGUAGES = "availablelanguages";
    private final   String P_AVAILABLETHEMES    = "availablethemes";
    
    private final   String P_OPENDIRECTORIES    = "opendirectories"; 
    
    private final   String P_DEFAULT_AVAILABLE_RULES = "defaultavailablerules";
    private final   String P_PROFILE_ENDINGS         = "profileendings";
    private final   String P_PROFILEPREFIX           = "profileprefix";
    
      // Banner files.
    private final   String P_HEADBANNER         = "headbanner";  
    private final   String P_FOOTBANNER         = "footbanner";   
    
      // Title
    private final   String P_TITLE               = "title";      
    
      // Paths
    private final   String P_AUTHORIZATION_PATH  = "authorization_path";   
    private final   String P_BANNERS_PATH        = "banners_path";
    private final   String P_CA_PATH             = "ca_path";
    private final   String P_CONFIG_PATH         = "config_path";   
    private final   String P_HELP_PATH           = "help_path"; 
    private final   String P_IMAGES_PATH         = "images_path";
    private final   String P_LANGUAGE_PATH       = "language_path";
    private final   String P_LOG_PATH            = "log_path"; 
    private final   String P_RA_PATH             = "ra_path";
    private final   String P_THEME_PATH          = "theme_path"; 
    
    private final   String P_LANGUAGEFILENAME    =  "languagefilename"; 
    private final   String P_MAINFILENAME        =  "mainfilename"; 
    private final   String P_INDEXFILENAME       =  "indexfilename"; 
    private final   String P_MENUFILENAME        =  "menufilename"; 
    private final   String P_ERRORPAGE           =  "errorpage";  
    
    private final   String P_POSSIBLEENTRIESPERPAGE = "possibleentiresperpage";    
    
    // Private fields
    private    HashMap        config;
    private    UserPreference defaultuserpreference;
    
}
