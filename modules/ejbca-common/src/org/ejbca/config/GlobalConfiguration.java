/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package org.ejbca.config;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.configuration.ConfigurationBase;
import org.cesecore.util.StringTools;
import org.ejbca.core.model.InternalEjbcaResources;


/**
 * This is a  class containing global configuration parameters.
 *
 * @version $Id$
 */
public class GlobalConfiguration extends ConfigurationBase implements Serializable {

    private static final long serialVersionUID = -2051789798029184421L;

    private static final Logger LOG = Logger.getLogger(GlobalConfiguration.class);

    // Default Values
    public static final float LATEST_VERSION = 3f;
    
    public static final String EJBCA_VERSION = InternalConfiguration.getAppVersion();

    public static final String PREFEREDINTERNALRESOURCES = InternalEjbcaResources.PREFEREDINTERNALRESOURCES;
    public static final String SECONDARYINTERNALRESOURCES = InternalEjbcaResources.SECONDARYINTERNALRESOURCES;

    // Entries to choose from in userpreference part, defines the size of data to be displayed on one page.
    private final  String[] DEFAULTPOSSIBLEENTRIESPERPAGE = {"10" , "25" , "50" , "100"};
    // Entries to choose from in view log part, defines the size of data to be displayed on one page.
    private final  String[] DEFAULTPOSSIBLELOGENTRIESPERPAGE = {"10" , "25" , "50" , "100", "200", "400"};

    public static final String GLOBAL_CONFIGURATION_ID = "0";

    // Path added to baseurl used as default value in CRLDistributionPointURI field in Certificate Profile definitions.
    private static final  String   DEFAULTCRLDISTURIPATH  = "publicweb/webdist/certdist?cmd=crl&issuer=";

    // Path added to baseurl used as default value in DeltaCRLDistributionPointURI field in Certificate Profile definitions.
    private static final  String   DEFAULTDELTACRLDISTURIPATH  = "publicweb/webdist/certdist?cmd=deltacrl&issuer=";

    // Path added to baseurl used as default value in CRLDistributionPointURI field in Certificate Profile definitions.
    private static final  String   DEFAULTCRLDISTURIPATHDN  = "CN=TestCA,O=AnaTom,C=SE";


    // Path added to baseurl used as default value in OCSP Service Locator URI field in Certificate Profile definitions.
	private static final  String   DEFAULTOCSPSERVICELOCATORURIPATH = "publicweb/status/ocsp";

    // Default name of headbanner in web interface.
    private static final  String   DEFAULTHEADBANNER             = "head_banner.jsp";
    // Default name of footbanner page in web interface.
    private static final  String   DEFAULTFOOTBANNER             = "foot_banner.jsp";
    
    // Default list of nodes in cluster
    private static final Set<String> NODESINCLUSTER_DEFAULT      = new LinkedHashSet<>();

    // Title of ra admin web interface.
    private static final  String   DEFAULTEJBCATITLE             = InternalConfiguration.getAppNameCapital() + " Administration";

    // The base of help links
    public static final String HELPBASEURI = WebConfiguration.getDocBaseUri();

    // Default values for AutoEnroll
    private static final  String  AUTOENROLL_DEFAULT_ADSERVER = "dc1.company.local";
    private static final  int  AUTOENROLL_DEFAULT_ADPORT = 0;
    private static final  String  AUTOENROLL_DEFAULT_BASEDN_USER = "CN=Users,DC=company,DC=local";
    public static final  int  AUTOENROLL_DEFAULT_CA = -1;
    private static final  String  AUTOENROLL_DEFAULT_CONNECTIONDN = "CN=ADReader,CN=Users,DC=company,DC=local";
    private static final  String  AUTOENROLL_DEFAULT_CONNECTIONPWD = "foo123";
    private static final  boolean  AUTOENROLL_DEFAULT_SSLCONNECTION = false;
    private static final  boolean  AUTOENROLL_DEFAULT_USE = false;
    
    /** Default value for Enable Command Line Interface. */
    private static final boolean DEFAULTENABLECOMMANDLINEINTERFACE = true;
    private static final boolean DEFAULTENABLECOMMANDLINEINTERFACEDEFAULTUSER = true;
    
    private static final boolean DEFAULTPUBLICWEBCERTCHAINORDEROOTFIRST = true;
    
    // Default CT Logs
    private static final Map<Integer,CTLogInfo> CTLOGS_DEFAULT = new LinkedHashMap<>();
    /* By default the list is empty but it is possible to add logs here. 
    static {
        try {
            // The Base64 data is the public key.
            final CTLogInfo log = new CTLogInfo(
                "http://ct.googleapis.com/pilot/ct/v1/",
                Base64.decode(
                    ("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHT\n"+
                     "DM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==\n").getBytes("ASCII")));
            CTLOGS_DEFAULT.put(log.getLogId(), log);
        } catch (UnsupportedEncodingException e) { } // NOPMD can't do anything here
    }*/
    
    // Language codes. Observe the order is important
    public static final  int      EN                 = 0;
    public static final  int      SE                 = 1;

    // Public constants.
    public static final  String HEADERFRAME         = "topFrame";  // Name of header browser frame
    public static final  String MENUFRAME           = "leftFrame"; // Name of menu browser frame
    public static final  String MAINFRAME           = "mainFrame"; // Name of main browser frame
    public static final  String DOCWINDOW           = "_ejbcaDocWindow"; // Name of browser window used to display help

    // Private constants
    private static final   String ADMINPATH             = "raadminpath";
    private static final   String AVAILABLELANGUAGES    = "availablelanguages";
    private static final   String AVAILABLETHEMES       = "availablethemes";
    private static final   String PUBLICPORT            = "publicport";
    private static final   String PRIVATEPORT           = "privateport";
    private static final   String PUBLICPROTOCOL        = "publicprotocol";
    private static final   String PRIVATEPROTOCOL       = "privateprotocol";


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
    
    private static final   String ENABLEICAOCANAMECHANGE       = "enableicaocanamechange";
    
    private static final   String NUMBEROFAPPROVALSTOVIEWPUK   = "numberofapprovalstoviewpuk";
    private static final   String HARDTOKENENCRYPTCA           = "hardtokenencryptca";
    private static final   String USEAPPROVALNOTIFICATIONS     = "useapprovalnotifications";
    private static final   String APPROVALADMINEMAILADDRESS    = "approvaladminemailaddress";
    private static final   String APPROVALNOTIFICATIONFROMADDR = "approvalnotificationfromaddr";
    
    private static final   String NODESINCLUSTER               = "nodesincluster";
    
    private static final   String ENABLECOMMANDLINEINTERFACE   = "enablecommandlineinterface";
    private static final   String ENABLECOMMANDLINEINTERFACEDEFAULTUSER = "enablecommandlineinterfacedefaultuser";

    // Configuration for Auto Enrollment
    private static final   String AUTOENROLL_USE = "autoenroll.use";
    private static final   String AUTOENROLL_ADSERVER = "autoenroll.adserver";
    private static final   String AUTOENROLL_ADPORT = "autoenroll.adport";
    private static final   String AUTOENROLL_SSLCONNECTION = "autoenroll.sslconnection";
    private static final   String AUTOENROLL_CONNECTIONDN = "autoenroll.connectiondn";
    private static final   String AUTOENROLL_CONNECTIONPWD = "autoenroll.connectionpwd";
    private static final   String AUTOENROLL_BASEDN_USER = "autoenroll.basedn.user";
    private static final   String AUTOENROLL_CA = "autoenroll.caid";
    
      // Paths
    private static final   String AUTHORIZATION_PATH  = "authorization_path";
    private static final   String BANNERS_PATH        = "banners_path";
    private static final   String CA_PATH             = "ca_path";
    private static final   String CONFIG_PATH         = "data_path";
    private static final   String HELP_PATH           = "help_path";
    private static final   String IMAGES_PATH         = "images_path";
    private static final   String LANGUAGE_PATH       = "language_path";
    private static final   String LOG_PATH            = "log_path";
    private static final   String REPORTS_PATH        = "reports_path";
    private static final   String RA_PATH             = "ra_path";
    private static final   String THEME_PATH          = "theme_path";
    private static final   String HARDTOKEN_PATH      = "hardtoken_path";
    
    private static final   String CTLOGS              = "ctlogs";
    
    private static final   String STATEDUMP_LOCKDOWN  = "statedump_lockdown";

    private static final   String LANGUAGEFILENAME      =  "languagefilename";
    private static final   String MAINFILENAME          =  "mainfilename";
    private static final   String INDEXFILENAME         =  "indexfilename";
    private static final   String MENUFILENAME          =  "menufilename";
    private static final   String ERRORPAGE             =  "errorpage";
    private static final   String IECSSFILENAMEPOSTFIX  =  "iecssfilenamepostfix";
    
    private static final String PUBLICWEBCERTCHAINORDEROOTFIRST = "publicwebcertchainorderrootfirst";
            
    /** Creates a new instance of GlobalConfiguration */
    public GlobalConfiguration()  {
       super();

       setEjbcaTitle(DEFAULTEJBCATITLE);
       setEnableEndEntityProfileLimitations(true);  // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
       setEnableAuthenticatedUsersOnly(false);  // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
       setEnableKeyRecovery(false);  // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
       setIssueHardwareTokens(false);  // Still needed for 100% up-time upgrade from before EJBCA 6.3.0
       setEnableIcaoCANameChange(false);
    }
    
    
    /** Initializes a new global configuration with data used in ra web interface. */
    public void initialize(String adminpath, String availablelanguages, String availablethemes,
                           String publicport, String privateport, String publicprotocol, String privateprotocol){
       
       String tempadminpath = adminpath.trim();

       if(tempadminpath == null) {
         tempadminpath = "";
       }
       if(!tempadminpath.endsWith("/") && !tempadminpath.equals("")){
         tempadminpath = tempadminpath + "/";   // Add ending '/'
       }
       if(tempadminpath.startsWith("/")){
         tempadminpath = tempadminpath.substring(1);   // Remove starting '/'
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
       data.put(REPORTS_PATH,tempadminpath+"reports");
       data.put(RA_PATH,tempadminpath+"ra");
       data.put(THEME_PATH,"themes");
       data.put(HARDTOKEN_PATH,tempadminpath+"hardtoken");

       data.put(LANGUAGEFILENAME,"languagefile");
       data.put(MAINFILENAME,"main.jsp");
       data.put(INDEXFILENAME,"index.jsp");
       data.put(MENUFILENAME,"adminmenu.jsp");
       data.put(ERRORPAGE,"errorpage.jsp");
       data.put(IECSSFILENAMEPOSTFIX,"_ie-fixes");

       setHeadBanner(DEFAULTHEADBANNER);
       setFootBanner(DEFAULTFOOTBANNER);

    }
    
    public void initializeAdminWeb() {
        initialize("adminweb", WebConfiguration.getAvailableLanguages(), "default_theme.css,second_theme.css", 
                ""+WebConfiguration.getPublicHttpPort(), ""+WebConfiguration.getPrivateHttpsPort(), "http", "https");
    }

    /** Checks if global datauration have been initialized. */
    public boolean isInitialized(){
      return data.get(AVAILABLELANGUAGES)!=null;
    }

    /** Method used by the Admin GUI. */
    public   String getBaseUrl(String requestServerName) {    
    	return (String) data.get(GlobalConfiguration.PRIVATEPROTOCOL) + "://" + 
    	            requestServerName  + "/" +
    	            InternalConfiguration.getAppNameLower() + "/";
   }
    
    public String getBaseUrl() {    
    	return (String) data.get(GlobalConfiguration.PRIVATEPROTOCOL) + "://" + 
    	           WebConfiguration.getHostName() + ":" +
    	           (String) data.get(GlobalConfiguration.PRIVATEPORT) + "/" +
    	           InternalConfiguration.getAppNameLower() + "/";
   }
        
    public String getAdminWebPath(){return (String) data.get(ADMINPATH);}

    public String getStandardCRLDistributionPointURI(){
        return getStandardCRLDistributionPointURINoDN() + DEFAULTCRLDISTURIPATHDN;
    }
    
    public String getStandardCRLDistributionPointURINoDN(){
        String retval = getBaseUrl();
        retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
        retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval+= DEFAULTCRLDISTURIPATH;
        return retval;
    }
    
    public String getStandardCRLIssuer() {
    	return DEFAULTCRLDISTURIPATHDN;
    }

    public String getStandardDeltaCRLDistributionPointURI(){
    	return getStandardDeltaCRLDistributionPointURINoDN() + DEFAULTCRLDISTURIPATHDN;
    }
        
    public String getStandardDeltaCRLDistributionPointURINoDN(){
        String retval = getBaseUrl();
        retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
        retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
        retval+= DEFAULTDELTACRLDISTURIPATH;
        return retval;
    }
        
	public String getStandardOCSPServiceLocatorURI(){
		String retval = getBaseUrl();
		retval =retval.replaceFirst((String) data.get(PRIVATEPROTOCOL), (String) data.get(PUBLICPROTOCOL));
		retval =retval.replaceFirst((String) data.get(PRIVATEPORT), (String) data.get(PUBLICPORT));
		retval+= DEFAULTOCSPSERVICELOCATORURIPATH;
		return retval;
	}        

     /** Checks the themes path for css files and returns an array of filenames
     *  without the ".css" ending. */
    public   String[] getAvailableThemes() {
       String[] availablethemes;
       availablethemes =  getAvailableThemesAsString().split(",");
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

    /** Returns the default available theme used by administrator preferences. */
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
    public   String getReportsPath() {return (String) data.get(REPORTS_PATH);}
    public   String getRaPath() {return (String) data.get(RA_PATH);}
    public   String getThemePath() {return (String) data.get(THEME_PATH);}
    public   String getHardTokenPath() {return (String) data.get(HARDTOKEN_PATH);}

    public   String getLanguageFilename(){return (String) data.get(LANGUAGEFILENAME);}
    public   String getMainFilename(){return (String) data.get(MAINFILENAME);}
    public   String getIndexFilename(){return (String) data.get(INDEXFILENAME);}
    public   String getMenuFilename(){return (String) data.get(MENUFILENAME);}
    public   String getErrorPage(){return (String) data.get(ERRORPAGE);}
    public   String getIeCssFilenamePostfix(){return (String) data.get(IECSSFILENAMEPOSTFIX);}

    public   String[] getPossibleEntiresPerPage(){return DEFAULTPOSSIBLEENTRIESPERPAGE;}
    public   String[] getPossibleLogEntiresPerPage(){return DEFAULTPOSSIBLELOGENTRIESPERPAGE;}

    public   String getAvailableLanguagesAsString(){return (String) data.get(AVAILABLELANGUAGES);}
    public   String getAvailableThemesAsString(){return (String) data.get(AVAILABLETHEMES);}

    public boolean getEnableEndEntityProfileLimitations() { return getBoolean(ENABLEEEPROFILELIMITATIONS, true); }
    public void setEnableEndEntityProfileLimitations(final boolean value) { putBoolean(ENABLEEEPROFILELIMITATIONS, value); }

    public boolean getEnableAuthenticatedUsersOnly() { return getBoolean(ENABLEAUTHENTICATEDUSERSONLY, false);}
    public void setEnableAuthenticatedUsersOnly(final boolean value) { putBoolean(ENABLEAUTHENTICATEDUSERSONLY, value);}

    public boolean getEnableKeyRecovery() { return getBoolean(ENABLEKEYRECOVERY, false); }
    public void setEnableKeyRecovery(final boolean value) { putBoolean(ENABLEKEYRECOVERY, value);}

    public boolean getIssueHardwareTokens() { return getBoolean(ISSUEHARDWARETOKENS, false);}
    public void setIssueHardwareTokens(final boolean value) { putBoolean(ISSUEHARDWARETOKENS, value);}
    
    public boolean getEnableIcaoCANameChange() { return getBoolean(ENABLEICAOCANAMECHANGE, false); }
    public void setEnableIcaoCANameChange(final boolean value) { putBoolean(ENABLEICAOCANAMECHANGE, value);}
    
   /**
    * @return the number of required approvals to access sensitive hard token data (default 0)
    */
    public int getNumberOfApprovalsToViewPUK(){
    	Object num = data.get(NUMBEROFAPPROVALSTOVIEWPUK);
        if(num == null){
        	return 0;
        }  	
    	return ((Integer) num).intValue();
    }
    
    public void setNumberOfApprovalsToViewPUK(int numberOfHardTokenApprovals){ 
    	data.put(NUMBEROFAPPROVALSTOVIEWPUK, Integer.valueOf(numberOfHardTokenApprovals));
    }
    
    /**
     * @return the caid of the CA that should encrypt hardtoken data in the database. if CAid is 0 is the data stored unencrypted.
     */
     public   int getHardTokenEncryptCA(){
     	Object num = data.get(HARDTOKENENCRYPTCA);
         if(num == null){
         	return 0;
         }
     	
     	return ((Integer) num).intValue();
     }
     
     /**
      * @param hardTokenEncryptCA the caid of the CA that should encrypt hardtoken data in the database. if CAid is 0 is the data stored unencrypted.
      */
     public void setHardTokenEncryptCA(int hardTokenEncryptCA){ 
     	data.put(HARDTOKENENCRYPTCA, Integer.valueOf(hardTokenEncryptCA));
     }
    
    /** @return true of email notification of requested approvals should be sent (default false) */
     @Deprecated // Used during upgrade to EJBCA 6.6.0
     public boolean getUseApprovalNotifications() { return getBoolean(USEAPPROVALNOTIFICATIONS, false); }
     /**
      * Returns the email address to the administrators that should recieve notification emails
      * should be an alias to all approval administrators default "" never null
      */
     @Deprecated // Used during upgrade to EJBCA 6.6.0
     public String getApprovalAdminEmailAddress() {
         final Object value = data.get(APPROVALADMINEMAILADDRESS);
         return value == null ? "" : (String) value;
     }      
     /** @return the email address used in the from field of approval notification emails */
     @Deprecated // Used during upgrade to EJBCA 6.6.0
     public String getApprovalNotificationFromAddress() {
         final Object value = data.get(APPROVALNOTIFICATIONFROMADDR);
         return value == null ? "" : (String) value;
     }      
   
       public void setAutoEnrollADServer(String server) { data.put(AUTOENROLL_ADSERVER, server); }
       public String getAutoEnrollADServer() {
    	   String ret = (String) data.get(AUTOENROLL_ADSERVER);
   		   return (ret == null ? AUTOENROLL_DEFAULT_ADSERVER : ret);
       }
       public void setAutoEnrollADPort(int caid) { data.put(AUTOENROLL_ADPORT, Integer.valueOf(caid)); }
       public int getAutoEnrollADPort() {
    	   Integer ret = (Integer) data.get(AUTOENROLL_ADPORT);
   		   return (ret == null ? AUTOENROLL_DEFAULT_ADPORT : ret);
       }
       public void setAutoEnrollBaseDNUser(String baseDN) { data.put(AUTOENROLL_BASEDN_USER, baseDN); }
       public String getAutoEnrollBaseDNUser() {
    	   String ret = (String) data.get(AUTOENROLL_BASEDN_USER);
   		   return (ret == null ? AUTOENROLL_DEFAULT_BASEDN_USER : ret);
   	   }
       public void setAutoEnrollCA(int caid) { data.put(AUTOENROLL_CA, Integer.valueOf(caid)); }
       public int getAutoEnrollCA() {
    	   Integer ret = (Integer) data.get(AUTOENROLL_CA);
    	   return (ret == null ? AUTOENROLL_DEFAULT_CA : ret);
       }
       public void setAutoEnrollConnectionDN(String connectionDN) { data.put(AUTOENROLL_CONNECTIONDN, connectionDN); }
       public String getAutoEnrollConnectionDN() {
    	   String ret = (String) data.get(AUTOENROLL_CONNECTIONDN);
   		   return (ret == null ? AUTOENROLL_DEFAULT_CONNECTIONDN : ret);
       }
       public void setAutoEnrollConnectionPwd(String connectionPwd) { 
           data.put(AUTOENROLL_CONNECTIONPWD, StringTools.obfuscateIfNot(connectionPwd));
       }
       public String getAutoEnrollConnectionPwd() {
    	   String ret = (String) data.get(AUTOENROLL_CONNECTIONPWD);
   		   return (ret == null ? AUTOENROLL_DEFAULT_CONNECTIONPWD : StringTools.deobfuscateIf(ret));
       }
       public void setAutoEnrollSSLConnection(final boolean value) { putBoolean(AUTOENROLL_SSLCONNECTION, value); }
       public boolean getAutoEnrollSSLConnection() { return getBoolean(AUTOENROLL_SSLCONNECTION, AUTOENROLL_DEFAULT_SSLCONNECTION); }

       public void setAutoEnrollUse(final boolean value) { putBoolean(AUTOENROLL_USE, value); }
       public boolean getAutoEnrollUse() { return getBoolean(AUTOENROLL_USE, AUTOENROLL_DEFAULT_USE); }
       
       public void setNodesInCluster(final Set<String> nodes) { data.put(NODESINCLUSTER, nodes); }
       @SuppressWarnings("unchecked")
       public Set<String> getNodesInCluster() {
           // In an earlier version (<5.0.11) this was a HashSet, not a LinkedHashSet. Using a HashSet causes order to be non-deterministic, that makes it possible
           // to get verification failures if using Database Protection. This was then changed to a LinkedHashSet that guarantees order. 
           // Therefore we try to ensure that a LinkedHashSet is returned, seamlessly upgrading any old HashSet. 
           // If an old object is in the database, after a getNodesInCluster(),  setNodesInCluster() and saveGlobalConfiguration() it should be a LinkedHashSet in the database. 
           Set<String> ret = null;
           Object o = data.get(NODESINCLUSTER);
           if (o != null && !(o instanceof LinkedHashSet<?>)) {
               LOG.debug("Converting GlobalConfiguration NodesInCluster from "+o.getClass().getName()+" to LinkedHashSet.");
               ret = new LinkedHashSet<>((Collection<String>)o);
           } else {
               ret = (Set<String>)o; 
           }
           return (ret == null ? NODESINCLUSTER_DEFAULT : ret);
       }

       public void setEnableCommandLineInterface(final boolean value) { putBoolean(ENABLECOMMANDLINEINTERFACE, value); }
       public boolean getEnableCommandLineInterface() { return getBoolean(ENABLECOMMANDLINEINTERFACE, DEFAULTENABLECOMMANDLINEINTERFACE); }
       
       public void setEnableCommandLineInterfaceDefaultUser(final boolean value) { putBoolean(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, value); }
       public boolean getEnableCommandLineInterfaceDefaultUser() { return getBoolean(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, DEFAULTENABLECOMMANDLINEINTERFACEDEFAULTUSER); }
       
    public boolean getPublicWebCertChainOrderRootFirst() {
        return getBoolean(PUBLICWEBCERTCHAINORDEROOTFIRST, DEFAULTPUBLICWEBCERTCHAINORDEROOTFIRST);
    }
    
    public void setPublicWebCertChainOrderRootFirst(boolean value) {
        putBoolean(PUBLICWEBCERTCHAINORDEROOTFIRST, value);
    }
       
    @SuppressWarnings("unchecked")
    public Map<Integer,CTLogInfo> getCTLogs() {
        final Map<Integer,CTLogInfo> ret = (Map<Integer,CTLogInfo>)data.get(CTLOGS);
        return (ret == null ? CTLOGS_DEFAULT : ret);
    }
    
    public void setCTLogs(Map<Integer,CTLogInfo> ctlogs) {
        data.put(CTLOGS, ctlogs);
    }
       
    public void addCTLog(CTLogInfo ctlog) {
        HashMap<Integer,CTLogInfo> logs = new LinkedHashMap<>(getCTLogs());
        logs.put(ctlog.getLogId(), ctlog);
        setCTLogs(logs);
    }
    
    public void removeCTLog(int ctlogId) {
        HashMap<Integer,CTLogInfo> logs = new LinkedHashMap<>(getCTLogs());
        logs.remove(ctlogId);
        setCTLogs(logs);
    }
    
    public boolean getStatedumpLockedDown() {
        return getBoolean(STATEDUMP_LOCKDOWN, true);
    }
    
    public void setStatedumpLockedDown(final boolean value) {
        data.put(STATEDUMP_LOCKDOWN, value);
    }

    @Override
    public float getLatestVersion(){
       return LATEST_VERSION;
    }

    @Override
    public void upgrade(){
    	if(Float.compare(LATEST_VERSION, getVersion()) != 0) {
    		// New version of the class, upgrade
    		if(data.get(HARDTOKEN_PATH) == null){
    			data.put(HARDTOKEN_PATH, ((String) data.get(ADMINPATH) + "hardtoken"));
    		}
    		if(data.get(REPORTS_PATH) == null){
    			data.put(REPORTS_PATH, ((String) data.get(ADMINPATH) + "reports"));
    		}
    		if(data.get(ENABLECOMMANDLINEINTERFACEDEFAULTUSER) == null) {
    		        data.put(ENABLECOMMANDLINEINTERFACEDEFAULTUSER, Boolean.TRUE);
    		}
    		if(data.get(ENABLEICAOCANAMECHANGE) == null) {
                data.put(ENABLEICAOCANAMECHANGE, Boolean.FALSE);
        }
    		data.put(VERSION,  Float.valueOf(LATEST_VERSION));    		
    	}
    }

    @Override
    public String getConfigurationId() {
        return GLOBAL_CONFIGURATION_ID;
    }
}
