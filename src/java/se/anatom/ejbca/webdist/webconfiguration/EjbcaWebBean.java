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
 
package se.anatom.ejbca.webdist.webconfiguration;

import java.net.URLDecoder;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.Collection;
import java.util.Date;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;

import se.anatom.ejbca.authorization.AuthenticationFailedException;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocal;
import se.anatom.ejbca.authorization.IAuthorizationSessionLocalHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocal;
import se.anatom.ejbca.ca.publisher.IPublisherSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocal;
import se.anatom.ejbca.hardtoken.IHardTokenSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.ra.IUserAdminSessionLocal;
import se.anatom.ejbca.ra.IUserAdminSessionLocalHome;
import se.anatom.ejbca.ra.raadmin.AdminPreference;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocal;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionLocalHome;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.ServiceLocator;
import se.anatom.ejbca.util.ServiceLocatorException;

/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @author  Philip Vendil
 * @version $Id: EjbcaWebBean.java,v 1.46 2005-05-19 06:15:13 herrvendil Exp $
 */
public class EjbcaWebBean implements java.io.Serializable {

    private static Logger log = Logger.getLogger(EjbcaWebBean.class);

    // Public Constants.
    public static final int AUTHORIZED_RA_VIEW_RIGHTS        = 0;
    public static final int AUTHORIZED_RA_EDIT_RIGHTS        = 1;
    public static final int AUTHORIZED_RA_CREATE_RIGHTS      = 2;
    public static final int AUTHORIZED_RA_DELETE_RIGHTS      = 3;
    public static final int AUTHORIZED_RA_REVOKE_RIGHTS      = 4;
    public static final int AUTHORIZED_RA_HISTORY_RIGHTS     = 5;
    public static final int AUTHORIZED_HARDTOKEN_VIEW_RIGHTS = 6;
    public static final int AUTHORIZED_CA_VIEW_CERT          = 7;
    public static final int AUTHORIZED_RA_KEYRECOVERY_RIGHTS = 8;

    private static final int AUTHORIZED_FIELD_LENGTH     = 9;
    private static final String[] AUTHORIZED_RA_RESOURCES = {"/ra_functionality/view_end_entity", "/ra_functionality/edit_end_entity",
                                                             "/ra_functionality/create_end_entity", "/ra_functionality/delete_end_entity",
                                                             "/ra_functionality/revoke_end_entity","/ra_functionality/view_end_entity_history",
                                                             "/ra_functionality/view_hardtoken","/ca_functionality/view_certificate",
                                                             "/ra_functionality/keyrecovery"};

    // Private Fields.
    private ILogSessionLocal               logsession;
    private AdminPreferenceDataHandler     adminspreferences;
    private AdminPreference                currentadminpreference;
    private GlobalConfiguration            globalconfiguration;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private AuthorizationDataHandler       authorizedatahandler;
    private WebLanguages                   adminsweblanguage;
    private String                         usercommonname = "";
    private String                         certificatefingerprint;
    private X509Certificate[]              certificates;
    private InformationMemory              informationmemory;
    private boolean                        initialized=false;
    private boolean                        errorpage_initialized=false;
    private Boolean[]                      raauthorized;
    private Admin                          administrator;

    

    /** Creates a new instance of EjbcaWebBean */
    public EjbcaWebBean() {
      initialized=false;
      raauthorized = new Boolean[AUTHORIZED_FIELD_LENGTH];
    }


    private void commonInit() throws Exception {
        ServiceLocator locator = ServiceLocator.getInstance();

    	IRaAdminSessionLocalHome raadminsessionhome = (IRaAdminSessionLocalHome) locator.getLocalHome(IRaAdminSessionLocalHome.COMP_NAME);
    	IRaAdminSessionLocal raadminsession = raadminsessionhome.create();

    	ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) locator.getLocalHome(ILogSessionLocalHome.COMP_NAME);
    	logsession = logsessionhome.create();

    	ICAAdminSessionLocalHome caadminsessionhome = (ICAAdminSessionLocalHome) locator.getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
    	ICAAdminSessionLocal caadminsession = caadminsessionhome.create();

    	ICertificateStoreSessionLocalHome certificatestoresessionhome = (ICertificateStoreSessionLocalHome) locator.getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
    	ICertificateStoreSessionLocal certificatestoresession = certificatestoresessionhome.create();

    	IAuthorizationSessionLocalHome authorizationsessionhome = (IAuthorizationSessionLocalHome) locator.getLocalHome(IAuthorizationSessionLocalHome.COMP_NAME);
    	IAuthorizationSessionLocal authorizationsession = authorizationsessionhome.create();

    	IHardTokenSessionLocalHome hardtokensessionhome = (IHardTokenSessionLocalHome) locator.getLocalHome(IHardTokenSessionLocalHome.COMP_NAME);
    	IHardTokenSessionLocal hardtokensession = hardtokensessionhome.create();

        IPublisherSessionLocalHome publishersessionhome = (IPublisherSessionLocalHome) locator.getLocalHome(IPublisherSessionLocalHome.COMP_NAME);
    	IPublisherSessionLocal publishersession = publishersessionhome.create();               		
    	
    	globaldataconfigurationdatahandler =  new GlobalConfigurationDataHandler(administrator, raadminsession, authorizationsession);        
    	globalconfiguration = this.globaldataconfigurationdatahandler.loadGlobalConfiguration();       
		if(informationmemory == null){		  
    	  informationmemory = new InformationMemory(administrator, caadminsession, raadminsession, authorizationsession, certificatestoresession, hardtokensession, publishersession, globalconfiguration);
		}
    	authorizedatahandler = new AuthorizationDataHandler(administrator, informationmemory, authorizationsession);
    	
    }
    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String resource) throws Exception{
    	
    	certificates = (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );
    	if(certificates == null) throw new AuthenticationFailedException("Client certificate required.");

    	String userdn = "";
    	
    	if(!initialized){
    		administrator = new Admin(certificates[0]) ;
    		
    		commonInit();
            ServiceLocator locator = ServiceLocator.getInstance();
    		IUserAdminSessionLocalHome adminsessionhome = (IUserAdminSessionLocalHome) locator.getLocalHome(IUserAdminSessionLocalHome.COMP_NAME);
    		IUserAdminSessionLocal  adminsession = adminsessionhome.create();
    		
    		adminspreferences = new AdminPreferenceDataHandler(administrator);
    		
    		// Check if user certificate is revoked
    		authorizedatahandler.authenticate(certificates[0]);
    		
    		// Check if certificate and user is an RA Admin
    		userdn = CertTools.getSubjectDN(certificates[0]);
    		log.debug("Verifying authorization of '"+userdn);    		
    		adminsession.checkIfCertificateBelongToAdmin(administrator, certificates[0].getSerialNumber(), certificates[0].getIssuerDN().toString());        
    		logsession.log(administrator, certificates[0], LogEntry.MODULE_ADMINWEB,  new java.util.Date(),null, null, LogEntry.EVENT_INFO_ADMINISTRATORLOGGEDIN,"");
    	}

    	try {
    		isAuthorized(URLDecoder.decode(resource,"UTF-8"));
    	} catch(AuthorizationDeniedException e) {
    		throw new AuthorizationDeniedException("You are not authorized to view this page.");
    	} catch(java.io.UnsupportedEncodingException e) {}
    	
    	
    	if(!initialized){
    		certificatefingerprint = CertTools.getFingerprintAsString(certificates[0]);
    		
    		// Get current admin preference.
    		currentadminpreference=null;
    		if(certificatefingerprint != null){
    			currentadminpreference = adminspreferences.getAdminPreference(certificatefingerprint);
    		}
    		if(currentadminpreference == null){
    			currentadminpreference = adminspreferences.getDefaultAdminPreference();
    		}
    		adminsweblanguage = new WebLanguages(globalconfiguration, currentadminpreference.getPreferedLanguage()
    				,currentadminpreference.getSecondaryLanguage());
    		
    		// set User Common Name
    		DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
    		usercommonname = dn.getField(DNFieldExtractor.CN,0);
    		
    		initialized=true;
    	}
    	return globalconfiguration;
    }


    public GlobalConfiguration initialize_errorpage(HttpServletRequest request) throws Exception{

      if(!errorpage_initialized){
              
        if(administrator == null){
          String remoteAddr = request.getRemoteAddr();
          administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);
        }
        commonInit(); 
        
        adminspreferences = new AdminPreferenceDataHandler(administrator);

        if(currentadminpreference == null){
           currentadminpreference = adminspreferences.getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguages(globalconfiguration, currentadminpreference.getPreferedLanguage()
                                             ,currentadminpreference.getSecondaryLanguage());
        errorpage_initialized=true;
      }
      return globalconfiguration;
    }

    /** Returns the current users common name */
    public String getUsersCommonName(){
      return usercommonname;
    }

    /** Returns the users certificate serialnumber, user to id the adminpreference. */
    public String getCertificateFingerprint(){
      return certificatefingerprint;
    }


    /** Return the admins selected theme including it's trailing '.css' */
    public String getCssFile(){
      return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentadminpreference.getTheme() + ".css";
    }

    /** Returns the admins prefered language */
    public int getPreferedLanguage() {
      return currentadminpreference.getPreferedLanguage();
    }

    /** Returns the admins secondary language. */
    public int getSecondaryLanguage() {
      return currentadminpreference.getSecondaryLanguage();
    }

    public int getEntriesPerPage(){
      return currentadminpreference.getEntriesPerPage();
    }

    public int getLogEntriesPerPage(){
      return currentadminpreference.getLogEntriesPerPage();
    }

    public void setLogEntriesPerPage(int logentriesperpage) throws Exception{
        currentadminpreference.setLogEntriesPerPage(logentriesperpage);
        if(existsAdminPreference()){
          adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint,currentadminpreference);
        }else{
          addAdminPreference(currentadminpreference);
        }
    }

    public int getLastFilterMode(){ return currentadminpreference.getLastFilterMode();}
    public void setLastFilterMode(int lastfiltermode) throws Exception{
        currentadminpreference.setLastFilterMode(lastfiltermode);
        if(existsAdminPreference()){
          adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint,currentadminpreference);
        }else{
          addAdminPreference(currentadminpreference);
        }
    }
    public int getLastLogFilterMode(){ return currentadminpreference.getLastLogFilterMode();}
    public void setLastLogFilterMode(int lastlogfiltermode) throws Exception{
        currentadminpreference.setLastLogFilterMode(lastlogfiltermode);
        if(existsAdminPreference()){
          adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint,currentadminpreference);
        }else{
          addAdminPreference(currentadminpreference);
        }
    }

    public int getLastEndEntityProfile(){ return currentadminpreference.getLastProfile();}
    public void setLastEndEntityProfile(int lastprofile) throws Exception{
        currentadminpreference.setLastProfile(lastprofile);
        if(existsAdminPreference()){
          adminspreferences.changeAdminPreferenceNoLog(certificatefingerprint,currentadminpreference);
        }else{
          addAdminPreference(currentadminpreference);
        }
    }

    public Object clone() throws CloneNotSupportedException {
      return super.clone();
    }

    /* Checks if the admin have authorization to view the resource */
    public boolean isAuthorized(String resource) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){         
        returnval= authorizedatahandler.isAuthorized(administrator,resource);
      }
      else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }

    /* Checks if the admin have authorization to view the resource without performing any logging. Used by menu page */
    public boolean isAuthorizedNoLog(String resource) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){
        returnval= authorizedatahandler.isAuthorizedNoLog(administrator,resource);
      }
      else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }


    /* A more optimezed authorization verison to check if the admin have authorization to view the url without performing any logging.
     * AUTHORIZED_RA.. contants should be used.*/
    public boolean isAuthorizedNoLog(int resource) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){
        if(raauthorized[resource] == null)
          raauthorized[resource] = Boolean.valueOf(authorizedatahandler.isAuthorizedNoLog(new Admin(certificates[0]),AUTHORIZED_RA_RESOURCES[resource]));

        returnval = raauthorized[resource].booleanValue();
      }
      else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }

    public String getBaseUrl(){return globalconfiguration.getBaseUrl();}

    /* Returns the current admins preference */
    public AdminPreference getAdminPreference() throws Exception{
      AdminPreference returnval = adminspreferences.getAdminPreference(certificatefingerprint);
      if(returnval==null)
        returnval = currentadminpreference;
      return returnval;
    }

    /* Returns the admin preferences database */
    public AdminPreferenceDataHandler getAdminPreferences() {
      return adminspreferences;
    }

    public AuthorizationDataHandler getAuthorizationDataHandler(){
       return  authorizedatahandler;
    }

    /* Returns the global configuration */
    public GlobalConfiguration getGlobalConfiguration() {
      return this.informationmemory.getGlobalConfiguration();
    }

     /**  A functions that returns wanted helpfile in prefered language.
     *   The parameter helpfilename should the wanted filename without language infix.
     *   For example: given helpfilename 'cahelp.html' would return 'cahelp.en.html'
     *   if english was the users prefered language. */
    public String getHelpfileInfix(String helpfilename) {
      String returnedurl=null;
      String [] strs = adminsweblanguage.getAvailableLanguages();
      int index = currentadminpreference.getPreferedLanguage();
      String prefered = strs[index];
      prefered = prefered.toLowerCase();
      String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()]
                                           .toLowerCase();

      String helpfile = helpfilename.substring(0,helpfilename.lastIndexOf('.'));
      String postfix  = helpfilename.substring(helpfilename.lastIndexOf('.')+1);

      String preferedfilename = "/" + globalconfiguration.getHelpPath()+"/"
                                + helpfile + "." + prefered + "." + postfix;

      String preferedurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getHelpPath()+"/"
                          + helpfile + "." + prefered + "." + postfix;

      String secondaryurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getHelpPath()+"/"
                          + helpfile + "." + secondary + "." + postfix;

      if(this.getClass().getResourceAsStream(preferedfilename) != null)
        returnedurl = preferedurl;
      else
        returnedurl = secondaryurl;

      return returnedurl;
    }

    /**  A functions that returns wanted imagefile in prefered language and theme. If none of the language
     *   specific images are found the original imagefilename will be returned.
     *
     *   The priority of filenames are int the following order
     *   1. imagename.theme.preferedlanguage.jpg/gif
     *   2. imagename.theme.secondarylanguage.jpg/gif
     *   3. imagename.theme.jpg/gif
     *   4. imagename.preferedlanguage.jpg/gif
     *   5. imagename.secondarylanguage.jpg/gif
     *   6. imagename.jpg/gif
     *
     *   The parameter imagefilename should the wanted filename without language infix.
     *   For example: given imagefilename 'caimg.gif' would return 'caimg.en.gif'
     *   if english was the users prefered language. It's important that all letters i imagefilename is lowercase.*/

    public String getImagefileInfix(String imagefilename) {
      String returnedurl=null;
      String [] strs = adminsweblanguage.getAvailableLanguages();
      int index = currentadminpreference.getPreferedLanguage();
      String prefered = strs[index];
      prefered = prefered.toLowerCase();
      String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()]
                                           .toLowerCase();

      String imagefile = imagefilename.substring(0,imagefilename.lastIndexOf('.'));
      String theme     = currentadminpreference.getTheme().toLowerCase();
      String postfix   = imagefilename.substring(imagefilename.lastIndexOf('.')+1);

      String preferedthemefilename = "/" + globalconfiguration .getImagesPath()+"/"
                                + imagefile + "." + theme + "." + prefered + "." + postfix;
      String secondarythemefilename = "/" + globalconfiguration .getImagesPath()+"/"
                                + imagefile + "." + theme + "." + secondary + "." + postfix;
      String themefilename =  "/" + globalconfiguration .getImagesPath()+"/"
                                + imagefile + "." + theme + "."  + postfix;

      String preferedfilename = "/" + globalconfiguration .getImagesPath()+"/"
                                + imagefile + "." + prefered + "." + postfix;

      String secondaryfilename = "/" + globalconfiguration .getImagesPath()+"/"
                                 + imagefile + "." + secondary + "." + postfix;

       String preferedthemeurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + prefered + "." + postfix;

      String secondarythemeurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + secondary + "." + postfix;

      String imagethemeurl     = globalconfiguration .getBaseUrl()  + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + postfix;


      String preferedurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + prefered + "." + postfix;

      String secondaryurl = globalconfiguration .getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + secondary + "." + postfix;

      String imageurl     = globalconfiguration .getBaseUrl()  + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "."  + postfix;
      if(this.getClass().getResourceAsStream(preferedthemefilename) != null)
        returnedurl = preferedthemeurl;
      else{
        if(this.getClass().getResourceAsStream(secondarythemefilename) != null)
          returnedurl = secondarythemeurl;
        else{
          if(this.getClass().getResourceAsStream(themefilename) != null)
            returnedurl = imagethemeurl;
          else{
            if(this.getClass().getResourceAsStream(preferedfilename) != null)
              returnedurl = preferedurl;
            else{
              if(this.getClass().getResourceAsStream(secondaryfilename) != null)
                 returnedurl = secondaryurl;
              else
                returnedurl = imageurl;
            }
          }
        }
      }
      return returnedurl;
    }


    public String[] getAvailableLanguages() {
        return adminsweblanguage.getAvailableLanguages();
    }
    public String getText(String template){
      return adminsweblanguage.getText(template);
    }

    public String printDate(Date date){
     return DateFormat.getDateInstance(DateFormat.SHORT).format(date);
    }

    public String printDateTime(Date date){
      return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(date);
    }

    public void reloadGlobalConfiguration() throws  Exception {
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
      informationmemory.systemConfigurationEdited(globalconfiguration);
    }

    public void saveGlobalConfiguration() throws Exception{
      globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);
      informationmemory.systemConfigurationEdited(globalconfiguration);
    }

    public boolean existsAdminPreference() throws Exception{
      return adminspreferences.existsAdminPreference(certificatefingerprint);
    }

    public void addAdminPreference(AdminPreference ap) throws Exception{
      currentadminpreference = ap;
      adminspreferences.addAdminPreference(certificatefingerprint,ap);
      adminsweblanguage = new WebLanguages(globalconfiguration, currentadminpreference.getPreferedLanguage()
                                          ,currentadminpreference.getSecondaryLanguage());
    }
  
    public Collection getAuthorizedCAIds(){
      return this.informationmemory.getAuthorizedCAIds();
    }
    
    public void changeAdminPreference(AdminPreference ap) throws Exception{
      currentadminpreference = ap;
      adminspreferences.changeAdminPreference(certificatefingerprint,ap);
      adminsweblanguage = new WebLanguages(globalconfiguration, currentadminpreference.getPreferedLanguage()
                                          ,currentadminpreference.getSecondaryLanguage());
    }

    public AdminPreference getDefaultAdminPreference() throws Exception{
      return adminspreferences.getDefaultAdminPreference();
    } // getDefaultAdminPreference()

    public void saveDefaultAdminPreference(AdminPreference dap) throws Exception{
      adminspreferences.saveDefaultAdminPreference(dap);

      // Reload preferences
      currentadminpreference = adminspreferences.getAdminPreference(certificatefingerprint);
      if(currentadminpreference == null){
         currentadminpreference = adminspreferences.getDefaultAdminPreference();
      }
      adminsweblanguage = new WebLanguages(globalconfiguration, currentadminpreference.getPreferedLanguage()
                                          ,currentadminpreference.getSecondaryLanguage());
    } // saveDefaultAdminPreference
    
    public InformationMemory getInformationMemory(){
      return this.informationmemory;   
    }
    
    public Admin getAdminObject(){
    	return this.administrator;    
    }

    /** Returns the default content encoding used in JSPs. Reads the env-entry contentEncoding from web.xml.
     * 
     * @return The content encoding set in the webs env-entry java:comp/env/contentEncoding, or ISO-8859-1 (default), never returns null.
     */
    public String getDefaultContentEncoding() {
        String ret = null;
        try {
            ret = ServiceLocator.getInstance().getString("java:comp/env/contentEncoding");            
        } catch (ServiceLocatorException e) {
            log.debug("Can not find any default content encoding, using hard default ISO-8859-1.");
            ret = "ISO-8859-1";            
        }
        if (ret == null) {
            log.debug("Can not find any default content encoding, using hard default ISO-8859-1.");
            ret = "ISO-8859-1";
        } 
        return ret;
    }
}
