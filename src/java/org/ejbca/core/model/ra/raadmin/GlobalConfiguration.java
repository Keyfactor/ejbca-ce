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
 
package org.ejbca.core.model.ra.raadmin;

import org.ejbca.core.model.UpgradeableDataHashMap;

/**
 * This is a  class containing global configuration parameters.
 *
 * @version $Id: GlobalConfiguration.java,v 1.4 2006-05-28 14:21:11 anatom Exp $
 */
public class GlobalConfiguration extends UpgradeableDataHashMap implements java.io.Serializable {

    // Default Values
    public static final float LATEST_VERSION = 1;
    
    public static final String EJBCA_VERSION = "@ejbca.version@";


    // Entries to choose from in userpreference part, defines the size of data to be displayed on one page.
    private final  String[] DEFAULTPOSSIBLEENTRIESPERPAGE = {"10" , "25" , "50" , "100"};
    // Entries to choose from in view log part, defines the size of data to be displayed on one page.
    private final  String[] DEFAULTPOSSIBLELOGENTRIESPERPAGE = {"10" , "25" , "50" , "100", "200", "400"};

    // Path added to baseurl used as default vaule in CRLDistributionPointURI field in Certificate Profile definitions.
    private static final  String   DEFAULTCRLDISTURIPATH  = "publicweb/webdist/certdist?cmd=crl&issuer=";
    
    // Path added to baseurl used as default vaule in CRLDistributionPointURI field in Certificate Profile definitions.
    private static final  String   DEFAULTCRLDISTURIPATHDN  = "CN=TestCA,O=AnaTom,C=SE";


    // Path added to baseurl used as default vaule in OCSP Service Locator URI field in Certificate Profile definitions.
	private static final  String   DEFAULTOCSPSERVICELOCATORURIPATH = "publicweb/status/ocsp";

    // Default name of headbanner in web interface.
    private static final  String   DEFAULTHEADBANNER             = "head_banner.jsp";
    // Default name of footbanner page in web interface.
    private static final  String   DEFAULTFOOTBANNER             = "foot_banner.jsp";

    // Title of ra admin web interface.
    private static final  String   DEFAULTEJBCATITLE             = "@EJBCA@ Administration";

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
       setEnableEndEntityProfileLimitations(true);
       setEnableAuthenticatedUsersOnly(false);
       setEnableKeyRecovery(false);
       setIssueHardwareTokens(false);
    }
    
    
    /** Initializes a new global datauration with data used in ra web interface. */
    public void initialize(String adminpath, String availablelanguages, String availablethemes,
                           String publicport, String privateport, String publicprotocol, String privateprotocol){
       
       String tempadminpath           = adminpath.trim();

       
       if(tempadminpath == null)
         tempadminpath = "";
       if(!tempadminpath.endsWith("/") && !tempadminpath.equals("")){
         tempadminpath = tempadminpath + "/";   // Add ending '/'
       }
       if(tempadminpath.startsWith("/")){
         tempadminpath =tempadminpath.substring(1);   // Remove starting '/'
       }

       
       
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
      return data.get(AVAILABLELANGUAGES)!=null;
    }

    /** Method used by the Admin GUI. */
    public   String getBaseUrl(String requestServerName) {    
    	return (String) data.get(GlobalConfiguration.PRIVATEPROTOCOL) + "://" + 
    	            requestServerName  + "/" +
    	           (String) data.get(GlobalConfiguration.APPLICATIONPATH);
   }
    
    public   String getBaseUrl() {    
    	return (String) data.get(GlobalConfiguration.PRIVATEPROTOCOL) + "://" + 
    	           (String) data.get(GlobalConfiguration.COMPUTERNAME) + ":" +
    	           (String) data.get(GlobalConfiguration.PRIVATEPORT) + "/" +
    	           (String) data.get(GlobalConfiguration.APPLICATIONPATH);
   }
        
    
    
    public void setComputerName(String computername){
    	data.put(COMPUTERNAME, computername);
    }
    
    public   void setApplicationPath(String applicationpath){
     // Add trailing '/' if it doesn't exists.
       if(!applicationpath.endsWith("/")){
         data.put(APPLICATIONPATH,applicationpath + "/");
       }
       else{
         data.put(APPLICATIONPATH,applicationpath);
       }
     }
    
    

    public String getAdminWebPath(){return (String) data.get(ADMINPATH);}

    public String getStandardCRLDistributionPointURI(){
        String retval = getBaseUrl();
        retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
        retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval+= DEFAULTCRLDISTURIPATH + DEFAULTCRLDISTURIPATHDN;
        return retval;
    }
    
    public String getStandardCRLDistributionPointURINoDN(){
        String retval = getBaseUrl();
        retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
        retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval+= DEFAULTCRLDISTURIPATH;
        return retval;
    }
        
	public String getStandardOCSPServiceLocatorURI(){
		String retval = getBaseUrl();
		retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
		retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
		retval+= DEFAULTOCSPSERVICELOCATORURIPATH;
		return retval;
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
      data.put(FOOTBANNER, "/" + ((String) data.get(BANNERS_PATH)) + "/" +foot);
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
    public   void    setEnableEndEntityProfileLimitations(boolean value){ data.put(ENABLEEEPROFILELIMITATIONS, Boolean.valueOf(value));}

    public   boolean getEnableAuthenticatedUsersOnly(){return ((Boolean) data.get(ENABLEAUTHENTICATEDUSERSONLY)).booleanValue();}
    public   void    setEnableAuthenticatedUsersOnly(boolean value){ data.put(ENABLEAUTHENTICATEDUSERSONLY, Boolean.valueOf(value));}

    public   boolean getEnableKeyRecovery(){return ((Boolean) data.get(ENABLEKEYRECOVERY)).booleanValue();}
    public   void    setEnableKeyRecovery(boolean value){ data.put(ENABLEKEYRECOVERY, Boolean.valueOf(value));}

    public   boolean getIssueHardwareTokens(){return ((Boolean) data.get(ISSUEHARDWARETOKENS)).booleanValue();}
    public   void    setIssueHardwareTokens(boolean value){ data.put(ISSUEHARDWARETOKENS, Boolean.valueOf(value));}


    /** Implemtation of UpgradableDataHashMap function getLatestVersion */
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    /** Implemtation of UpgradableDataHashMap function upgrade. */

    public void upgrade(){
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
    		// New version of the class, upgrade
    		if(data.get(HARDTOKEN_PATH) == null){
    			data.put(HARDTOKEN_PATH, ((String) data.get(ADMINPATH) + "hardtoken"));
    		}
    		
    		data.put(VERSION, new Float(LATEST_VERSION));    		
    	}
    }

    // Private fields.

    // Private constants
    //private static final   String BASEURL             = "baseurl";
    private static final   String COMPUTERNAME  = "computername";
    private static final   String APPLICATIONPATH  = "applicationpath";
    private static final   String ADMINPATH          = "raadminpath";
    private static final   String AVAILABLELANGUAGES = "availablelanguages";
    private static final   String AVAILABLETHEMES    = "availablethemes";
    private static final   String PUBLICPORT         = "publicport";
    private static final   String PRIVATEPORT        = "privateport";
    private static final   String PUBLICPROTOCOL     = "publicprotocol";
    private static final   String PRIVATEPROTOCOL    = "privateprotocol";


      // Title
    private static final   String TITLE              = "title";
      // Banner files.
    private static final   String HEADBANNER         = "headbanner";
    private static final   String FOOTBANNER         = "footbanner";
      // Other configuration.
    private static final   String ENABLEEEPROFILELIMITATIONS   = "endentityprofilelimitations";
    private static final   String ENABLEAUTHENTICATEDUSERSONLY = "authenticatedusersonly";
    private static final   String ENABLEKEYRECOVERY            = "enablekeyrecovery";
    private static final   String ISSUEHARDWARETOKENS          = "issuehardwaretokens";
      // Paths
    private static final   String AUTHORIZATION_PATH  = "authorization_path";
    private static final   String BANNERS_PATH        = "banners_path";
    private static final   String CA_PATH             = "ca_path";
    private static final   String CONFIG_PATH         = "data_path";
    private static final   String HELP_PATH           = "help_path";
    private static final   String IMAGES_PATH         = "images_path";
    private static final   String LANGUAGE_PATH       = "language_path";
    private static final   String LOG_PATH            = "log_path";
    private static final   String RA_PATH             = "ra_path";
    private static final   String THEME_PATH          = "theme_path";
    private static final   String HARDTOKEN_PATH      = "hardtoken_path";

    private static final   String LANGUAGEFILENAME    =  "languagefilename";
    private static final   String MAINFILENAME        =  "mainfilename";
    private static final   String INDEXFILENAME       =  "indexfilename";
    private static final   String MENUFILENAME        =  "menufilename";
    private static final   String ERRORPAGE           =  "errorpage";

}
