/*
 * GlobalConfiguration.java
 *
 * Created on den 28 mars 2002, 10:02
 */

package se.anatom.ejbca.webdist.webconfiguration;

import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.HashMap;
import java.util.Properties;
import javax.naming.InitialContext;
import javax.naming.Context;


/**
 *  This is a static class containing global configuration parameters and default
 *  user preferences.
 *
 * @author  Philip Vendil
 */
public class GlobalConfiguration implements java.io.Serializable {
  
    // Default Values
    
    private final static String[] OPENDIRECTORIES        = {"/","/banners","/images","/help","/themes","/languages"};
    private final static String[] HIDDENDIRECTORIES      = {"/banners","/images","/help","/themes","/languages","/WEB-INF"};
    private final static String[] POSSIBLEENTRIESPERPAGE = {"10" , "25" , "50" , "100"};
   
    private final static String   HEADBANNER             = "head_banner.jsp";
    private final static String   FOOTBANNER             = "foot_banner.jsp";
    
    private final static String   EJBCATITLE             = "Enterprise Java Bean Certificate Authority";
    
    // Observe the order is important
    public final static int      EN                 = 0; 
    public final static int      SE                 = 1;
    
    // Public constants.
    public final static String HEADERFRAME         = "topFrame";
    public final static String MENUFRAME           = "leftFrame";
    public final static String MAINFRAME           = "mainFrame";   
    

    
    /** Creates a new instance of GlobalConfiguration */
    public GlobalConfiguration() throws javax.naming.NamingException {    
       defaultuserpreference = new UserPreference();
       config = new HashMap();
 
       InitialContext ictx = new InitialContext();
       Context myenv = (Context) ictx.lookup("java:comp/env");            
       String tempbaseurl = ((String) myenv.lookup("BASEURL")).trim();
       String tempdocroot = ((String) myenv.lookup("DOCUMENTROOT")).trim();
       String tempraadminpath =  ((String) myenv.lookup("RAADMINDIRECTORY")).trim();
       String tempavailablelanguages = ((String) myenv.lookup("AVAILABLELANGUAGES")).trim();
       String tempavailablethemes = ((String) myenv.lookup("AVAILABLETHEMES")).trim();
       
       if(!tempbaseurl.endsWith("/")){
         tempbaseurl = tempbaseurl + "/";   // Remove ending '/'
       }
       if(tempdocroot.endsWith("/")){
         tempdocroot = tempdocroot.substring(0,tempdocroot.length()-1);   // Remove ending '/'
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
       setDocumentRoot(tempdocroot + "/src/ra/web/raadmin/"); 
       config.put(P_RAADMINPATH,tempraadminpath);
       config.put(P_AVAILABLELANGUAGES,tempavailablelanguages);
       config.put(P_AVAILABLETHEMES,tempavailablethemes);
       
       // Add Ra Admin Path to the default open and hidden directories strings.
       String tempraadminpath2 = tempraadminpath;
       String[] tempopendirectories = new String[OPENDIRECTORIES.length];
       String[] temphiddendirectories = new String[HIDDENDIRECTORIES.length];
       
       if(!tempraadminpath.equals(""))
         tempraadminpath2 = "/" + tempraadminpath.substring(0,tempraadminpath.length() - 1);
     
       for(int i=0; i < OPENDIRECTORIES.length ; i++){
          tempopendirectories[i] = tempraadminpath2 + OPENDIRECTORIES[i]; 
       }
       for(int i=0; i < HIDDENDIRECTORIES.length ; i++){
          temphiddendirectories[i] = tempraadminpath2 + HIDDENDIRECTORIES[i];            
       } 
       
       config.put(P_OPENDIRECTORIES,tempopendirectories);
       config.put(P_HIDDENDIRECTORIES,temphiddendirectories);
       
       setEjbcaTitle(EJBCATITLE);
       
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
    
       setHeadBanner(HEADBANNER);
       setFootBanner(FOOTBANNER);
       
       config.put(P_POSSIBLEENTRIESPERPAGE,POSSIBLEENTRIESPERPAGE);
   
    }
    
    // Configurable fields.
    public static void setBasicWebConfiguration(String burl, String docroot,
                                                String opendirs,
                                                String hiddendirs){
        setBaseUrl(burl);
        setDocumentRoot(docroot);
        setOpenDirectories(opendirs);
        setOpenDirectories(hiddendirs);      
    }
    
    public static void setDefaultPreference(String todo){
         
    }
    
    
    public static String getBaseUrl() {return (String) config.get(P_BASEURL);}
    public static void setBaseUrl(String burl){
      // Add trailing '/' if it doesn't exists.  
      if(!burl.endsWith("/")){
        config.put(P_BASEURL,burl + "/");    
      }
      else{
        config.put(P_BASEURL,burl);    
      }
    }
    
    public static String getDocumentRoot() {return (String) config.get(P_DOCUMENTROOT);}
    public static void setDocumentRoot(String docroot){    
       // Addtrailing '/' if it doesn't exists.  
      if(!docroot.endsWith("/")){
        config.put(P_DOCUMENTROOT,docroot + "/");    
      }
      else{
        config.put(P_DOCUMENTROOT,docroot);  
      }
    }   
    
    public static String getRaAdminPath(){return (String) config.get(P_RAADMINPATH);}

    public static String[] getOpenDirectories() {return (String[]) config.get(P_OPENDIRECTORIES);} 
    // Returns all opendirectories as a comma-separated string.
    public static String getOpenDirectoriesAsString(){
      String[] opendirectories = (String[]) config.get(P_OPENDIRECTORIES); 
      String returnvalue="";
      for(int i=0; i < opendirectories.length -1; i++){
         returnvalue += opendirectories[i] + ", ";   
      }
      returnvalue+= opendirectories[opendirectories.length-1];
      
      return returnvalue;
    }
    /** The opendirectories parameter is a comma separated string containing the 
        open directories*/
    public static void setOpenDirectories(String opendirs){
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

    public static String[] getHiddenDirectories() {return (String[]) config.get(P_HIDDENDIRECTORIES);}
    // Returns all opendirectories as a comma-separated string.
    public static String getHiddenDirectoriesAsString(){
      String[] hiddendirectories = (String[]) config.get(P_HIDDENDIRECTORIES);
      String returnvalue = "";
      for(int i=0; i < hiddendirectories.length -1; i++){           
         returnvalue += hiddendirectories[i] + ", ";   
      }
      returnvalue+= hiddendirectories[hiddendirectories.length -1];      
      return returnvalue;
    }
    
    /** The hiddendirectories parameter is a comma separated string containing the 
        hidden directories*/
    public static void setHiddenDirectories(String hiddendirs){
      hiddendirs=hiddendirs.trim();  
      if(hiddendirs.endsWith(",")){
        hiddendirs=hiddendirs.substring(0,hiddendirs.length()-1);   
      }
      String[] dirs = hiddendirs.split(",");
    
      for(int i=0; i < dirs.length; i++){
         dirs[i]=dirs[i].trim();   
         // Add a heading "/" if it doesn't exists. 
         if(!dirs[i].startsWith("/")){
           dirs[i]= "/" + dirs[i];   
         }
      }
      
      config.put(P_HIDDENDIRECTORIES,dirs);
    }
    
     /** Checks the themes paht for css files and returns an array of filenames
     *  without the ".css" ending. */
    
    public static String[] getAvailableThemes() {
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
     public static UserPreference getRealDefaultPreference(){  
       return defaultuserpreference;
    }   
    
    public static UserPreference getDefaultPreference(){
       UserPreference returnvalue=null;
       try{
         returnvalue = (UserPreference) defaultuserpreference.clone();
       }catch( Exception e){   
       }
       return returnvalue;
    }
    

    
    public static String getHeadBanner() {return (String) config.get(P_HEADBANNER);}
    public static String getHeadBannerFilename(){
      String returnval = (String) config.get(P_HEADBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public static void setHeadBanner(String head){config.put(P_HEADBANNER, ((String) config.get(P_RAADMINPATH)) +
                                                             ((String) config.get(P_BANNERS_PATH)) + "/" + head);}
    public static String getFootBanner() {return (String) config.get(P_FOOTBANNER);} 
    public static String getFootBannerFilename(){
      String returnval = (String) config.get(P_FOOTBANNER);
      return returnval.substring(returnval.lastIndexOf('/')+1);  
    }
    public static void setFootBanner(String foot){config.put(P_FOOTBANNER,  "/" + ((String) config.get(P_BANNERS_PATH)) + "/" +foot);}
    
    public static String getEjbcaTitle() {return (String) config.get(P_TITLE);}
    public static void setEjbcaTitle(String ejbcatitle) {config.put(P_TITLE,ejbcatitle);}
    // Static fields
       
    public static String getAuthorizationPath() {return (String) config.get(P_AUTHORIZATION_PATH);}  
    public static String getBannersPath() {return (String) config.get(P_BANNERS_PATH);}
    public static String getCaPath() {return (String) config.get(P_CA_PATH);}
    public static String getConfigPath() {return (String) config.get(P_CONFIG_PATH);}
    public static String getHelpPath() {return (String) config.get(P_HELP_PATH);}
    public static String getImagesPath() {return (String) config.get(P_IMAGES_PATH);}
    public static String getLanguagePath() {return (String) config.get(P_LANGUAGE_PATH);}       
    public static String getLogPath() {return (String) config.get(P_LOG_PATH);}        
    public static String getRaPath() {return (String) config.get(P_RA_PATH);}
    public static String getThemePath() {return (String) config.get(P_THEME_PATH);}
            
    public static String getLanguageFilename(){return (String) config.get(P_LANGUAGEFILENAME);}
    public static String getMainFilename(){return (String) config.get(P_MAINFILENAME);}   
    public static String getIndexFilename(){return (String) config.get(P_INDEXFILENAME);}   
    public static String getMenuFilename(){return (String) config.get(P_MENUFILENAME);}   
    public static String getErrorPage(){return (String) config.get(P_ERRORPAGE);}   
    
    public static String[] getPossibleEntiresPerPage(){return (String[]) config.get(P_POSSIBLEENTRIESPERPAGE);}      

    public static String getAvailableLanguagesAsString(){return (String) config.get(P_AVAILABLELANGUAGES);} 
    public static String getAvailableThenesAsString(){return (String) config.get(P_AVAILABLETHEMES);}         
    
    // Private fields.
    // Overloaded from the serialize interface. Used to save and restore the configuration.
    private void writeObject(ObjectOutputStream out) throws IOException {
      out.writeObject(config);
      out.writeObject(defaultuserpreference);
    }    

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
      config = (HashMap) in.readObject();
      defaultuserpreference = (UserPreference) in.readObject();
    }    
    
    // Private constants
      // Basic configuration
    private final static String P_BASEURL            = "baseurl";
    private final static String P_DOCUMENTROOT       = "documentroot";
    private final static String P_RAADMINPATH        = "raadminpath";
    private final static String P_AVAILABLELANGUAGES = "availablelanguages";
    private final static String P_AVAILABLETHEMES    = "availablethemes";
    
    private final static String P_OPENDIRECTORIES    = "opendirectories"; 
    private final static String P_HIDDENDIRECTORIES  = "hiddendirectories"; 
        
      // Banner files.
    private final static String P_HEADBANNER         = "headbanner";  
    private final static String P_FOOTBANNER         = "footbanner";   
    
      // Title
    private final static String P_TITLE               = "title";      
    
      // Paths
    private final static String P_AUTHORIZATION_PATH  = "authorization_path";   
    private final static String P_BANNERS_PATH        = "banners_path";
    private final static String P_CA_PATH             = "ca_path";
    private final static String P_CONFIG_PATH         = "config_path"; 
    private final static String P_HELP_PATH           = "help_path"; 
    private final static String P_IMAGES_PATH         = "images_path";
    private final static String P_LANGUAGE_PATH       = "language_path";
    private final static String P_LOG_PATH            = "log_path"; 
    private final static String P_RA_PATH             = "ra_path";
    private final static String P_THEME_PATH          = "theme_path"; 
    
    private final static String P_LANGUAGEFILENAME    =  "languagefilename"; 
    private final static String P_MAINFILENAME        =  "mainfilename"; 
    private final static String P_INDEXFILENAME       =  "indexfilename"; 
    private final static String P_MENUFILENAME        =  "menufilename"; 
    private final static String P_ERRORPAGE           =  "errorpage";  
    
    private final static String P_POSSIBLEENTRIESPERPAGE = "possibleentiresperpage";    
    
    // Private fields
    private  static HashMap        config;
    private  static UserPreference defaultuserpreference;
    private  static Properties     basicconfig;
    
}
