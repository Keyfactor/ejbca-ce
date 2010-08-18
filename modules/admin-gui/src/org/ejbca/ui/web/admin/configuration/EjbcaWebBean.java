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
 
package org.ejbca.ui.web.admin.configuration;

import java.io.Serializable;
import java.net.InetAddress;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Locale;

import javax.ejb.EJBException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.ejbca.config.WebConfiguration;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.ejb.authorization.AuthorizationSession;
import org.ejbca.core.ejb.authorization.AuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSession;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.publisher.PublisherSession;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSession;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSession;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.log.LogSession;
import org.ejbca.core.ejb.log.LogSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSession;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSession;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSession;
import org.ejbca.core.ejb.ra.userdatasource.UserDataSourceSessionRemote;
import org.ejbca.core.model.authorization.AuthenticationFailedException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.core.model.ra.raadmin.AdminPreference;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.util.EjbLocalHelper;
import org.ejbca.core.model.util.EjbRemoteHelper;
import org.ejbca.util.CertTools;
import org.ejbca.util.HTMLTools;
import org.ejbca.util.dn.DNFieldExtractor;
import org.ejbca.util.keystore.KeyTools;

/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @author  Philip Vendil
 * @version $Id$
 */
public class EjbcaWebBean implements Serializable {

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

    // TODO: Use local interfaces here
    //private EjbLocalHelper ejb = new EjbLocalHelper();
    private EjbRemoteHelper ejb = new EjbRemoteHelper();
    private LogSession logSession = ejb.getLogSession();
    private CertificateStoreSession certificateStoreSession = ejb.getCertStoreSession();
    private CAAdminSession caAdminSession = ejb.getCAAdminSession();
    private UserAdminSession userAdminSession = ejb.getUserAdminSession();
    private RaAdminSession raAdminSession = ejb.getRAAdminSession();
    private AuthorizationSession authorizationSession = ejb.getAuthorizationSession();
    private HardTokenSession hardTokenSession = ejb.getHardTokenSession();
    private PublisherSession publisherSession = ejb.getPublisherSession();
    private UserDataSourceSession userDataSourceSession = ejb.getUserDataSourceSession();

    private AdminPreferenceDataHandler     adminspreferences;
    private AdminPreference                currentadminpreference;
    private GlobalConfiguration            globalconfiguration;
    private ServletContext                 servletContext = null;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private AuthorizationDataHandler       authorizedatahandler;
    private WebLanguages                   adminsweblanguage;
    private String                         usercommonname = "";
    private String                         certificatefingerprint;
    /** Certificates for administrator logging into admin-GUI */
    private X509Certificate[]              certificates;
    private InformationMemory              informationmemory;
    private boolean                        initialized=false;
    private boolean                        errorpage_initialized=false;
    private Boolean[]                      raauthorized;
    private Admin                          administrator;
    private String                         requestServerName;

    /** Creates a new instance of EjbcaWebBean */
    public EjbcaWebBean() {
    	initialized = false;
    	raauthorized = new Boolean[AUTHORIZED_FIELD_LENGTH];
    }

    private void commonInit() throws Exception {
        //ServiceLocator locator = ServiceLocator.getInstance();

    	if ((administrator == null) && (certificates == null)) {
    		throw new AuthenticationFailedException("Client certificate required.");
    	} else if (certificates != null) {
    		administrator = userAdminSession.getAdmin(certificates[0]);    		
    	} // else we have already defined an administrator, for example in initialize_errorpage

    	globaldataconfigurationdatahandler =  new GlobalConfigurationDataHandler(administrator, raAdminSession, authorizationSession);        
    	globalconfiguration = this.globaldataconfigurationdatahandler.loadGlobalConfiguration();       
    	if (informationmemory == null) {
    		informationmemory = new InformationMemory(administrator, caAdminSession, raAdminSession, authorizationSession, certificateStoreSession, hardTokenSession,
    				publisherSession, userDataSourceSession, globalconfiguration);
    	}
    	authorizedatahandler = new AuthorizationDataHandler(administrator, informationmemory, authorizationSession, caAdminSession);
    	
    }
    /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request, String resource) throws Exception{
    	
    	certificates = (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );
    	if(certificates == null || certificates.length == 0) {
    		throw new AuthenticationFailedException("Client certificate required.");
    	}

    	
    	String userdn = "";
    	
    	if(!initialized){
    		requestServerName = getRequestServerName(request);
    		
    		commonInit();
    		adminspreferences = new AdminPreferenceDataHandler(administrator);
    		
    		// Check if user certificate is revoked
    		certificateStoreSession.authenticate(certificates[0], WebConfiguration.getRequireAdminCertificateInDatabase());
    		
    		// Set ServletContext for reading language files from resources
    		servletContext = request.getSession(true).getServletContext();
    		
    		// Check if certificate and user is an RA Admin
    		userdn = CertTools.getSubjectDN(certificates[0]);
    		log.debug("Verifying authorization of '"+userdn);    		
    		userAdminSession.checkIfCertificateBelongToUser(administrator, CertTools.getSerialNumber(certificates[0]), CertTools.getIssuerDN(certificates[0]));        
    		logSession.log(administrator, certificates[0], LogConstants.MODULE_ADMINWEB,  new java.util.Date(),null, null, LogConstants.EVENT_INFO_ADMINISTRATORLOGGEDIN,"");
    	}

    	try {
    		isAuthorized(URLDecoder.decode(resource,"UTF-8"));
    	} catch(AuthorizationDeniedException e) {
    		throw new AuthorizationDeniedException("You are not authorized to view this page.");
    	} catch( EJBException e) {
    	    final Throwable cause = e.getCause();
    	    final String dbProblemMessage = getText("DATABASEDOWN");
    	    if ( cause instanceof SQLException ) {
    	        final Exception e1 = new Exception(dbProblemMessage);
    	        e1.initCause(e);
    	        throw e1;
    	    } else if ( cause.getMessage().indexOf("SQLException", 0)>=0 ) {
                final Exception e1 = new Exception(dbProblemMessage);
                e1.initCause(e);
                throw e1;
    	    }
    	    throw e;
    	}
    	
    	
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
    		adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage()
    				,currentadminpreference.getSecondaryLanguage());
    		
    		// set User Common Name
    		DNFieldExtractor dn = new DNFieldExtractor(userdn, DNFieldExtractor.TYPE_SUBJECTDN);
    		usercommonname = dn.getField(DNFieldExtractor.CN,0);
    		
    		initialized=true;
    	}
    	return globalconfiguration;
    }


    /**
     * Method that returns the servername, extracted from the HTTPServlet Request, 
     * no protocol, port or application path is returned
     * @return the server name requested
     */
    private String getRequestServerName(HttpServletRequest request) {    	
    	String requestURL = request.getRequestURL().toString();
    	
    	// Remove https://
    	requestURL = requestURL.substring(8);
    	int firstSlash = requestURL.indexOf("/");
    	// Remove application path
    	requestURL =requestURL.substring(0,firstSlash);
		
		return requestURL;
	}


	public GlobalConfiguration initialize_errorpage(HttpServletRequest request) throws Exception{

      if(!errorpage_initialized){
              
        if(administrator == null){
          String remoteAddr = request.getRemoteAddr();
          administrator = new Admin(Admin.TYPE_PUBLIC_WEB_USER, remoteAddr);
        }
        commonInit(); 
        
        adminspreferences = new AdminPreferenceDataHandler(administrator);

		// Set ServletContext for reading language files from resources
        servletContext = request.getSession(true).getServletContext();

        if(currentadminpreference == null){
           currentadminpreference = adminspreferences.getDefaultAdminPreference();
        }
        adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage()
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

    /** Return the IE fixes CSS of the admins selected theme including it's trailing '.css' */
    public String getIeFixesCssFile(){
      return globalconfiguration.getAdminWebPath() + globalconfiguration.getThemePath() + "/" + currentadminpreference.getTheme() + globalconfiguration.getIeCssFilenamePostfix() + ".css";
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
      } else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }

    /* Checks if the admin have authorization to view the resource without performing any logging. Used by menu page */
    public boolean isAuthorizedNoLog(String resource) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){
        returnval= authorizedatahandler.isAuthorizedNoLog(administrator,resource);
      } else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }


    /* A more optimized authorization version to check if the admin have authorization to view the url without performing any logging.
     * AUTHORIZED_RA.. constants should be used.*/
    public boolean isAuthorizedNoLog(int resource) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){
        if(raauthorized[resource] == null) {
        	// We don't bother to lookup the admin's username and email for this check..
        	raauthorized[resource] = Boolean.valueOf(authorizedatahandler.isAuthorizedNoLog(new Admin(certificates[0], null, null),AUTHORIZED_RA_RESOURCES[resource]));
        }
        returnval = raauthorized[resource].booleanValue();
      } else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }

    public String getBaseUrl(){return globalconfiguration.getBaseUrl(requestServerName);}
    public String getReportsPath(){return globalconfiguration.getReportsPath();}

    /* Returns the current admins preference */
    public AdminPreference getAdminPreference() throws Exception{
      AdminPreference returnval = adminspreferences.getAdminPreference(certificatefingerprint);
      if(returnval==null) {
        returnval = currentadminpreference;
      }
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

      String preferedurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getHelpPath()+"/"
                          + helpfile + "." + prefered + "." + postfix;

      String secondaryurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getHelpPath()+"/"
                          + helpfile + "." + secondary + "." + postfix;

      if(this.getClass().getResourceAsStream(preferedfilename) != null) {
        returnedurl = preferedurl;
      } else {
        returnedurl = secondaryurl;
      }
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

       String preferedthemeurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + prefered + "." + postfix;

      String secondarythemeurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + secondary + "." + postfix;

      String imagethemeurl     = getBaseUrl()  + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + postfix;


      String preferedurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + prefered + "." + postfix;

      String secondaryurl = getBaseUrl() + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + secondary + "." + postfix;

      String imageurl     = getBaseUrl()  + globalconfiguration .getAdminWebPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "."  + postfix;
      if(this.getClass().getResourceAsStream(preferedthemefilename) != null) {
    	  returnedurl = preferedthemeurl;
      } else {
    	  if(this.getClass().getResourceAsStream(secondarythemefilename) != null) {
    		  returnedurl = secondarythemeurl;
    	  } else {
    		  if(this.getClass().getResourceAsStream(themefilename) != null) {
    			  returnedurl = imagethemeurl;
    		  } else {
    			  if(this.getClass().getResourceAsStream(preferedfilename) != null) {
    				  returnedurl = preferedurl;
    			  } else {
    				  if(this.getClass().getResourceAsStream(secondaryfilename) != null) {
    					  returnedurl = secondaryurl;
    				  } else {
    					  returnedurl = imageurl;
    				  }
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
    /**
     * @param template the entry in the language file to get
     * @param unescape true if html entities should be unescaped (&auml; converted to the real char)
     * @return text string, possibly unescaped, or "template" if the template does not match any entry in the language files
     */
    public String getText(String template, boolean unescape){
        String str = getText(template);
        if (unescape == true) {
            str = HTMLTools.htmlunescape(str);
            //log.debug("String after unescape: "+str);
            // If unescape == true it most likely means we will be displaying a javascript
            str = HTMLTools.javascriptEscape(str);
            //log.debug("String after javascriptEscape: "+str);
        }
        return str;
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
      adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage()
                                          ,currentadminpreference.getSecondaryLanguage());
    }
  
    public Collection getAuthorizedCAIds(){
      return this.informationmemory.getAuthorizedCAIds();
    }
    
    public void changeAdminPreference(AdminPreference ap) throws Exception{
      currentadminpreference = ap;
      adminspreferences.changeAdminPreference(certificatefingerprint,ap);
      adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage()
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
      adminsweblanguage = new WebLanguages(servletContext, globalconfiguration, currentadminpreference.getPreferedLanguage()
                                          ,currentadminpreference.getSecondaryLanguage());
    } // saveDefaultAdminPreference
    
    public InformationMemory getInformationMemory(){
      return this.informationmemory;   
    }
    
    public Admin getAdminObject(){
    	return this.administrator;    
    }
    
    /**
     * Method returning all CA ids with CMS service enabled
     */
    public Collection getCAIdsWithCMSServiceActive(){
    	ArrayList<Integer> retval = new ArrayList<Integer>();
    	Collection<Integer> caids = caAdminSession.getAvailableCAs(administrator);
    	Iterator<Integer> iter = caids.iterator();
    	while(iter.hasNext()){
    		Integer caid = iter.next();
    		retval.add(caid);
    	}
    	return retval;
    }

    /**
     * Detect if "Unlimited Strength" Policy files has bean properly installed.
     * 
     * @return true if key strength is limited
     */
    public boolean isUsingExportableCryptography() {
    	return KeyTools.isUsingExportableCryptography();
    }
    
    /**
     * @return The host's name or "unknown" if it could not be determined.
     */
    public String getHostName() {
    	String hostname = "unknown";
    	try {
	        InetAddress addr = InetAddress.getLocalHost();    
	        // Get hostname
	        hostname = addr.getHostName();
	    } catch (UnknownHostException e) {
	    	// Ignored
	    }
	    return hostname;
    }
    
    /**
     * @return The current time on the server
     */
    public String getServerTime(){
    	SimpleDateFormat timeformat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ssz");
    	return timeformat.format(new Date());
    }

    /**
     * Uses the language in the Administration GUI to determine which locale is preferred. 
     * @return the locale of the Admin GUI
     */
    public Locale getLocale() {
    	Locale[] locales = DateFormat.getAvailableLocales();
    	Locale returnValue = null;
        String prefered = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getPreferedLanguage()].toLowerCase();
        String secondary = adminsweblanguage.getAvailableLanguages()[currentadminpreference.getSecondaryLanguage()].toLowerCase();
        if (prefered.equalsIgnoreCase("se")) {
        	prefered = "SV";
        }
        if (secondary.equalsIgnoreCase("se")) {
        	secondary = "SV";
        }
        for (int i=0; i<locales.length; i++) {
        	if ( locales[i].getLanguage().equalsIgnoreCase(prefered) ) {
            	returnValue = locales[i];
        	} else if ( returnValue == null && locales[i].getLanguage().equalsIgnoreCase(secondary) ) {
        		returnValue = locales[i];
        	}
        }
        if ( returnValue == null) {
        	returnValue = Locale.US;
        }
        return returnValue;
    }
    
    public boolean isHelpEnabled() { return !"disabled".equalsIgnoreCase(GlobalConfiguration.HELPBASEURI); }
    
    public String getHelpBaseURI() {
    	String helpBaseURI = GlobalConfiguration.HELPBASEURI;
    	if ("internal".equalsIgnoreCase(helpBaseURI)) {
    		return getBaseUrl() + "doc";
    	} else {
    		return helpBaseURI;
    	}
    }

    public String getHelpReference(String lastPart) {
    	if (!isHelpEnabled()) {
    		return "";
    	}
    	return "[<a href=\"" + getHelpBaseURI() +lastPart + "\" target=\"" + GlobalConfiguration.DOCWINDOW +
    		"\" title=\"" + getText("OPENHELPSECTION") + "\" >?</a>]";
    }

    public String getCleanOption(String parameter, String[] validOptions) throws Exception {
        for(int i=0; i<validOptions.length; i++){
            if(parameter.equals(validOptions[i]))   return parameter;
        }
        throw new Exception("Trying to set an invalid option.");
    }

}
