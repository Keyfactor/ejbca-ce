/*
 * EjbcaWebBean.java
 *
 * Created on den 28 mars 2002, 17:59
 */

package se.anatom.ejbca.webdist.webconfiguration;
import java.io.IOException;
import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import javax.servlet.http.HttpServletRequest;
import java.security.cert.CertificateFactory;
import java.net.URLDecoder;
import java.math.BigInteger;
import java.beans.*;
import javax.naming.*;
import javax.ejb.CreateException;
import javax.ejb.FinderException;
import java.io.Serializable;
import java.io.ObjectOutputStream;
import java.io.ObjectInputStream;
import java.io.FileNotFoundException;
import java.util.Properties;
import java.util.Date;
import java.text.DateFormat;
import java.rmi.RemoteException;
import java.util.Collection;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;

import se.anatom.ejbca.webdist.ejbcaathorization.EjbcaAthorization;
import se.anatom.ejbca.webdist.ejbcaathorization.AuthorizationDeniedException;
import se.anatom.ejbca.webdist.rainterface.DNFieldExtractor;
import se.anatom.ejbca.webdist.rainterface.UserView;

/**
 * The main bean for the web interface, it contains all basic functions.
 *
 * @author  Philip Vendil
 */
public class EjbcaWebBean {

    /** Creates a new instance of EjbcaWebBean */
    public EjbcaWebBean() throws IOException, NamingException, CreateException, FileNotFoundException,
                                 FinderException, RemoteException{
      globaldataconfigurationdatahandler =  new GlobalConfigurationDataHandler();
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
      userspreferences = new UsersPreferenceDataHandler();
      authorize = new EjbcaAthorization(globalconfiguration);
      authorizedatahandler = new AuthorizationDataHandler(globalconfiguration);
      weblanguages = new WebLanguages(globalconfiguration);
      initialized=false;
    }

    // Public Methods.

        /* Sets the current user and returns the global configuration */
    public GlobalConfiguration initialize(HttpServletRequest request) throws AuthorizationDeniedException,  IOException,
                                                              NamingException, CreateException, java.security.cert.CertificateException,
                                                              java.security.cert.CertificateExpiredException,  java.security.cert.CertificateNotYetValidException,
                                                              javax.ejb.FinderException{

      String userdn = "";

      CertificateFactory certfact =  CertificateFactory.getInstance("X.509");
      certificates =   (X509Certificate[]) request.getAttribute( "javax.servlet.request.X509Certificate" );

      if(certificates == null) throw new AuthorizationDeniedException("Client certificate required.");
      // Check if certificate is still valid
      if(!initialized){
        try{
          for(int i=0; i < certificates.length;i++){
            certificates[i].checkValidity();
          }
        }catch(Exception e){
           throw new AuthorizationDeniedException("Your certificates vality has expired.");
        }

        userdn = certificates[0].getSubjectX500Principal().toString();

        // Check if user certificae is revoked
        InitialContext jndicontext = new InitialContext();

        // Get the ICertificateStoreSession instance.
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome)
                                                               javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

        obj1 = jndicontext.lookup("UserAdminSession");
        IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSessionRemote  adminsession = adminsessionhome.create();

       try{
          if(certificatesession.isRevoked(certificates[0].getIssuerDN().toString(),certificates[0].getSerialNumber()) != null){
            // Certificate revoked
            throw new AuthorizationDeniedException("Your certificates has been revoked.");
          }
         }
         catch(RemoteException e){
            throw new AuthorizationDeniedException("Your certificate cannot be found in database.");
         }

        // Check if certificate belongs to a RA Admin
        UserAdminData userdata = adminsession.findUserBySubjectDN(userdn);
        if(userdata != null){
          UserView user = new UserView(userdata);
          if(user.getValue(UserView.TYPE_RAADMIN) == null)
            throw new  AuthorizationDeniedException("Your certificate do not belong to a RA Admin.");
          if(user.getValue(UserView.TYPE_RAADMIN).equals(UserView.FALSE))
            throw new  AuthorizationDeniedException("Your certificate do not belong to a RA Admin.");
        }else{
          throw new  AuthorizationDeniedException("Your certificate do not belong to any user.");
        }
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

    public String getLastProfileGroup(){ return currentuserpreference.getLastProfileGroup();}
    public void setLastProfileGroup(String lastprofilegroup) throws Exception{
        currentuserpreference.setLastProfileGroup(lastprofilegroup);
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
        returnval= authorize.isAthorized(certificates[0],url);
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

    /* Returns the Ejbca Authorization component */
    public EjbcaAthorization getAthorizationComponent() {
      return authorize;
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

    /**  A functions that returns wanted imagefile in prefered language. If none of the language
     *   specific images are found the original imagefilename will be returned.
     *
     *   The parameter imagefilename should the wanted filename without language infix.
     *   For example: given imagefilename 'caimg.html' would return 'caimg.en.html'
     *   if english was the users prefered language. */
    public String getImagefileInfix(String imagefilename) {
      String returnedurl=null;
      String prefered = WebLanguages.getAvailableLanguages()[currentuserpreference.getPreferedLanguage()]
                                          .toLowerCase();
      String secondary = WebLanguages.getAvailableLanguages()[currentuserpreference.getSecondaryLanguage()]
                                           .toLowerCase();

      String imagefile = imagefilename.substring(0,imagefilename.lastIndexOf('.'));
      String postfix  = imagefilename.substring(imagefilename.lastIndexOf('.')+1);

      String preferedfilename = "/" + globalconfiguration .getImagesPath()+"/"
                                + imagefile + "." + prefered + "." + postfix;

      String secondaryfilename = "/" + globalconfiguration .getImagesPath()+"/"
                                 + imagefile + "." + secondary + "." + postfix;

      String preferedurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + prefered + "." + postfix;

      String secondaryurl = globalconfiguration .getBaseUrl() + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "." + secondary + "." + postfix;

      String imageurl     = globalconfiguration .getBaseUrl()  + globalconfiguration .getRaAdminPath()
                          + globalconfiguration .getImagesPath()+"/"
                          + imagefile + "."  + postfix;

      if(this.getClass().getResourceAsStream(preferedfilename) != null)
        returnedurl = preferedurl;
      else{
        if(this.getClass().getResourceAsStream(secondaryfilename) != null)
          returnedurl = secondaryurl;
        else
          returnedurl = imageurl;
      }

      return returnedurl;
    }


    public String getText(String template){
      return usersweblanguage.getText(template);
    }

    public String printDate(Date date){
     return DateFormat.getDateInstance(DateFormat.SHORT).format(date);
    }

    public void reloadGlobalConfiguration() throws  Exception {
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
    }

    public void saveGlobalConfiguration() throws Exception{
      System.out.println("saving global title : " +  globalconfiguration.getEjbcaTitle() );
      globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);
    }

    public boolean existsUserPreference() throws Exception{
      return userspreferences.existsUserPreference(certificateserialnumber);
    }

    public void addUserPreference(UserPreference up) throws Exception{
      currentuserpreference = up;
      userspreferences.addUserPreference(certificateserialnumber,up);
    }


    public void changeUserPreference(UserPreference up) throws Exception{
      currentuserpreference = up;
      userspreferences.changeUserPreference(certificateserialnumber,up);
    }

    /**
     * Method to add an access rule.
     */

    public void addAvailableAccessRule(String name) throws RemoteException{
      authorizedatahandler.addAvailableAccessRule(name);
    } // addAvailableAccessRule

    /**
     * Method to add an Collection of access rules.
     */

    public void addAvailableAccessRules(Collection names) throws RemoteException{
      authorizedatahandler.addAvailableAccessRules(names);
    } //  addAvailableAccessRules

    /**
     * Method to remove an access rule.
     */

    public void removeAvailableAccessRule(String name)  throws RemoteException{
      authorizedatahandler.removeAvailableAccessRule(name);
    } // removeAvailableAccessRule

    /**
     * Method to remove an Collection of access rules.
     */

    public void removeAvailableAccessRules(Collection names)  throws RemoteException{
      authorizedatahandler.removeAvailableAccessRules(names);
    } // removeAvailableAccessRules

    /**
     * Method that returns a Collection of Strings containing all access rules.
     */

    public Collection getAvailableAccessRules() throws RemoteException{
       return authorizedatahandler.getAvailableAccessRules();
    } // getAvailableAccessRules

    /**
     * Checks wheither an access rule exists in the database.
     */

    public boolean existsAvailableAccessRule(String name) throws RemoteException{
      return authorizedatahandler.existsAvailableAccessRule(name);
    } // existsAvailableAccessRule

    // Private Fields.
    private UsersPreferenceDataHandler userspreferences;
    private UserPreference currentuserpreference;
    private GlobalConfiguration globalconfiguration;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private EjbcaAthorization authorize;
    private AuthorizationDataHandler authorizedatahandler;
    private WebLanguages weblanguages;
    private WebLanguages usersweblanguage;
    private String usercommonname = "";
    private BigInteger certificateserialnumber;
    private X509Certificate[] certificates;
    private boolean initialized=false;

}
