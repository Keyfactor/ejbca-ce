package se.anatom.ejbca.webdist.webconfiguration;

import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.net.URLDecoder;
import java.math.BigInteger;
import java.io.IOException;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.util.Properties;
import java.util.Date;
import java.text.DateFormat;
import java.rmi.RemoteException;
import java.util.Collection;

import org.apache.log4j.*;

import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.authorization.EjbcaAuthorization;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.LogEntry;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.authorization.AuthenticationFailedException;
import se.anatom.ejbca.ra.authorization.UserInformation;
import se.anatom.ejbca.ra.raadmin.DNFieldExtractor;
import se.anatom.ejbca.webdist.rainterface.UserView;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.UserPreference;

/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @author  Philip Vendil
 * @version $Id: EjbcaWebBean.java,v 1.14 2002-09-12 18:14:15 herrvendil Exp $
 */
public class EjbcaWebBean {

    private static Category cat = Category.getInstance(EjbcaWebBean.class.getName());

    /** Creates a new instance of EjbcaWebBean */
    public EjbcaWebBean() throws IOException, NamingException, CreateException,
                                 FinderException, RemoteException{                           
      initialized=false;
    }

    // Public Methods.

        /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request) throws Exception{

      String userdn = "";

      CertificateFactory certfact =  CertificateFactory.getInstance("X.509");
      certificates =   (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );

      if(certificates == null) throw new AuthenticationFailedException("Client certificate required.");
      // Check if certificate is still valid
      if(!initialized){
        Admin administrator = new Admin(certificates[0]) ;  
       
       
        globaldataconfigurationdatahandler =  new GlobalConfigurationDataHandler(administrator);
        globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
        userspreferences = new UsersPreferenceDataHandler(administrator);
        weblanguages = new WebLanguages(globalconfiguration);          
          
        userdn = certificates[0].getSubjectX500Principal().toString();
        
        // Check if user certificate is revoked
        InitialContext jndicontext = new InitialContext();

        Object obj1 = jndicontext.lookup("UserAdminSession");
        IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSessionRemote  adminsession = adminsessionhome.create(administrator);
        
        obj1 = jndicontext.lookup("LogSession");
        ILogSessionHome logsessionhome = (ILogSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ILogSessionHome.class);   
        logsession = logsessionhome.create();


        authorizedatahandler = new AuthorizationDataHandler(globalconfiguration, logsession, administrator);
        authorizedatahandler.authenticate(certificates[0]); 
        
        // Check if certificate belongs to a RA Admin
        cat.debug("Verifying authoirization of '"+userdn);
        
        // Check that user is administrator.
        adminsession.checkIfSubjectDNisAdmin(userdn);

        logsession.log(administrator, new java.util.Date(),null, null, LogEntry.EVENT_INFO_ADMINISTRATORLOGGEDIN,"");               
        
      }
      try{
        isAuthorized(URLDecoder.decode(request.getRequestURI(),"UTF-8"));
      }catch(AuthorizationDeniedException e){
         throw new AuthorizationDeniedException("You are not authorized to view this page.");
      }catch(java.io.UnsupportedEncodingException e) {}



      if(!initialized){
        certificateserialnumber = certificates[0].getSerialNumber();
        // Get current user.
        currentuserpreference=null;
        if(certificateserialnumber != null){
          currentuserpreference = userspreferences.getUserPreference(certificateserialnumber);
        }
        if(currentuserpreference == null){
           currentuserpreference = globalconfiguration.getDefaultPreference();
        }
        usersweblanguage = new WebLanguages( currentuserpreference.getPreferedLanguage()
                                          ,currentuserpreference.getSecondaryLanguage());

       // set User Common Name
        DNFieldExtractor dn = new DNFieldExtractor(userdn);
        usercommonname = dn.getField(DNFieldExtractor.COMMONNAME);

        initialized=true;
      }
      return globalconfiguration;
    }

    /** Returns the current users common name */
    public String getUsersCommonName(){
      return usercommonname;
    }

    /** Returns the users certificate serialnumber, user to id the userpreference. */
    public String getCertificateSerialNumber(){
      return certificateserialnumber.toString(16);
    }


    /** Return the users selected theme including it's trailing '.css' */
    public String getCssFile(){
      return globalconfiguration.getRaAdminPath() + globalconfiguration.getThemePath() + "/" + currentuserpreference.getTheme() + ".css";
    }

    /** Returns the users prefered language */
    public int getPreferedLanguage() {
      return currentuserpreference.getPreferedLanguage();
    }

    /** Returns the users secondary language. */
    public int getSecondaryLanguage() {
      return currentuserpreference.getSecondaryLanguage();
    }

    public int getEntriesPerPage(){
      return currentuserpreference.getEntriesPerPage();
    }
    
    public int getLogEntriesPerPage(){
      return currentuserpreference.getLogEntriesPerPage();        
    }

    public void setLogEntriesPerPage(int logentriesperpage) throws Exception{
        currentuserpreference.setLogEntriesPerPage(logentriesperpage);
        if(existsUserPreference()){
          changeUserPreference(currentuserpreference);
        }else{
          addUserPreference(currentuserpreference);
        }
    }
    
    public int getLastFilterMode(){ return currentuserpreference.getLastFilterMode();}
    public void setLastFilterMode(int lastfiltermode) throws Exception{
        currentuserpreference.setLastFilterMode(lastfiltermode);
        if(existsUserPreference()){
          changeUserPreference(currentuserpreference);
        }else{
          addUserPreference(currentuserpreference);
        }
    }
    public int getLastLogFilterMode(){ return currentuserpreference.getLastLogFilterMode();}
    public void setLastLogFilterMode(int lastlogfiltermode) throws Exception{
        currentuserpreference.setLastLogFilterMode(lastlogfiltermode);
        if(existsUserPreference()){
          changeUserPreference(currentuserpreference);
        }else{
          addUserPreference(currentuserpreference);
        }
    }
    
    public String getLastProfile(){ return currentuserpreference.getLastProfile();}
    public void setLastProfile(String lastprofile) throws Exception{
        currentuserpreference.setLastProfile(lastprofile);
        if(existsUserPreference()){
          changeUserPreference(currentuserpreference);
        }else{
          addUserPreference(currentuserpreference);
        }
    }

    public Object clone() throws CloneNotSupportedException {
      return super.clone();
    }

    /* Checks if the user have authorization to view the url */
    public boolean isAuthorized(String url) throws AuthorizationDeniedException {
      boolean returnval=false;
      if(certificates != null){           
        returnval= authorizedatahandler.isAuthorized(new UserInformation(certificates[0]),url);
      }
      else{
        throw new  AuthorizationDeniedException("Client certificate required.");
      }
      return returnval;
    }

    public String getBaseUrl(){return globalconfiguration.getBaseUrl();}

    /* Returns the current users preference */
    public UserPreference getUserPreference() throws Exception{
      UserPreference returnval = userspreferences.getUserPreference(certificateserialnumber);
      if(returnval==null)
        returnval = currentuserpreference;
      return returnval;
    }

    /* Returns the user preferences database */
    public UsersPreferenceDataHandler getUsersPreferences() {
      return userspreferences;
    }

    public AuthorizationDataHandler getAuthorizationDataHandler(){
       return  authorizedatahandler;
    }

    /* Returns the global configuration */
    public GlobalConfiguration getGlobalConfiguration() {
      return globalconfiguration;
    }

     /**  A functions that returns wanted helpfile in prefered language.
     *   The parameter helpfilename should the wanted filename without language infix.
     *   For example: given helpfilename 'cahelp.html' would return 'cahelp.en.html'
     *   if english was the users prefered language. */
    public String getHelpfileInfix(String helpfilename) {
      String returnedurl=null;
      String prefered = WebLanguages.getAvailableLanguages()[currentuserpreference.getPreferedLanguage()]
                                          .toLowerCase();
      String secondary = WebLanguages.getAvailableLanguages()[currentuserpreference.getSecondaryLanguage()]
                                           .toLowerCase();

      String helpfile = helpfilename.substring(0,helpfilename.lastIndexOf('.'));
      String postfix  = helpfilename.substring(helpfilename.lastIndexOf('.')+1);

      String preferedfilename = "/" + globalconfiguration.getHelpPath()+"/"
                                + helpfile + "." + prefered + "." + postfix;

      String secondaryfilename = "/" + globalconfiguration .getHelpPath()+"/"
                                 + helpfile + "." + secondary + "." + postfix;

      String preferedurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getHelpPath()+"/"
                          + helpfile + "." + prefered + "." + postfix;

      String secondaryurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
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
      String prefered = WebLanguages.getAvailableLanguages()[currentuserpreference.getPreferedLanguage()]
                                          .toLowerCase();
      String secondary = WebLanguages.getAvailableLanguages()[currentuserpreference.getSecondaryLanguage()]
                                           .toLowerCase();

      String imagefile = imagefilename.substring(0,imagefilename.lastIndexOf('.'));
      String theme     = currentuserpreference.getTheme().toLowerCase();
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
      
       String preferedthemeurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + prefered + "." + postfix;

      String secondarythemeurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + secondary + "." + postfix;

      String imagethemeurl     = globalconfiguration .getBaseUrl()  + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + theme + "." + postfix;     
      

      String preferedurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + prefered + "." + postfix;

      String secondaryurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + secondary + "." + postfix;

      String imageurl     = globalconfiguration .getBaseUrl()  + globalconfiguration .getRaAdminPath()
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


    public String getText(String template){
      return usersweblanguage.getText(template);
    }

    public String printDate(Date date){
     return DateFormat.getDateInstance(DateFormat.SHORT).format(date);
    }

    public String printDateTime(Date date){
      return DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(date);
    }    
    
    public void reloadGlobalConfiguration() throws  Exception {
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
    }

    public void saveGlobalConfiguration() throws Exception{
      globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);
    }

    public boolean existsUserPreference() throws Exception{
      return userspreferences.existsUserPreference(certificateserialnumber);
    }

    public void addUserPreference(UserPreference up) throws Exception{
      currentuserpreference = up;
      userspreferences.addUserPreference(certificateserialnumber,up);
      usersweblanguage = new WebLanguages( currentuserpreference.getPreferedLanguage()
                                          ,currentuserpreference.getSecondaryLanguage());
    }


    public void changeUserPreference(UserPreference up) throws Exception{
      currentuserpreference = up;
      userspreferences.changeUserPreference(certificateserialnumber,up);
      usersweblanguage = new WebLanguages(currentuserpreference.getPreferedLanguage()
                                          ,currentuserpreference.getSecondaryLanguage());
    }



    // Private Fields.
    private ILogSessionRemote              logsession; 
    private UsersPreferenceDataHandler     userspreferences;
    private UserPreference                 currentuserpreference;
    private GlobalConfiguration            globalconfiguration;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private AuthorizationDataHandler       authorizedatahandler;
    private WebLanguages                   weblanguages;
    private WebLanguages                   usersweblanguage;
    private String                         usercommonname = "";
    private BigInteger                     certificateserialnumber;
    private X509Certificate[]              certificates;
    private boolean                        initialized=false;

}
