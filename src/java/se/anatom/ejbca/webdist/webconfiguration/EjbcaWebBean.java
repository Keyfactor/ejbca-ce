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
import java.io.FileNotFoundException;
import java.io.FileInputStream;
import java.util.Properties;
import java.util.Date;
import java.text.DateFormat;
import java.rmi.RemoteException;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSession;
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
    public EjbcaWebBean() throws IOException, FileNotFoundException, NamingException, CreateException,
                                 FinderException, RemoteException{                          
      globaldataconfigurationdatahandler =  new GlobalConfigurationDataHandler();    
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();      
      userspreferences = new UsersPreferenceDataHandler();       
      authorize = new EjbcaAthorization();
      weblanguages = new WebLanguages(); 
    }
        
    // Public Methods.
    
        /* Sets the current user */
    public void initialize(HttpServletRequest request) throws AuthorizationDeniedException, FileNotFoundException, IOException, 
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
        // Get the ICertificateStoreSession instance.
        Properties jndienv = new Properties();
        jndienv.load(new FileInputStream(GlobalConfiguration.getDocumentRoot() +"/WEB-INF/jndi.properties"));
        InitialContext jndicontext = new InitialContext(jndienv);
        
        Object obj1 = jndicontext.lookup("CertificateStoreSession");
        ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) 
                                                               javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create(); 
        
        obj1 = jndicontext.lookup("UserAdminSession");
        IUserAdminSessionHome adminsessionhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);
        IUserAdminSession adminsession = adminsessionhome.create(); 
       
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
    public String getCssFile() {
      return currentuserpreference.getCssFile();  
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
    public UserPreference getUserPreference() throws RemoteException{
      return currentuserpreference;  
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
            System.out.println("EjbcaWebBean get global");  
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
      
      String preferedfilename = GlobalConfiguration.getDocumentRoot() 
                                + GlobalConfiguration.getHelpPath()+"/"
                                + helpfile + "." + prefered + "." + postfix;
      
      String secondaryfilename = GlobalConfiguration.getDocumentRoot()
                                 + GlobalConfiguration.getHelpPath()+"/"
                                 + helpfile + "." + secondary + "." + postfix;
      
      String preferedurl = GlobalConfiguration.getBaseUrl() + GlobalConfiguration.getRaAdminPath()
                          + GlobalConfiguration.getHelpPath()+"/"
                          + helpfile + "." + prefered + "." + postfix;
      
      String secondaryurl = GlobalConfiguration.getBaseUrl() + GlobalConfiguration.getRaAdminPath()
                          + GlobalConfiguration.getHelpPath()+"/"
                          + helpfile + "." + secondary + "." + postfix;
    
      if(new java.io.File(preferedfilename).exists())
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
      
      String preferedfilename = GlobalConfiguration.getDocumentRoot() 
                                + GlobalConfiguration.getImagesPath()+"/"
                                + imagefile + "." + prefered + "." + postfix;
      
      String secondaryfilename = GlobalConfiguration.getDocumentRoot()
                                 + GlobalConfiguration.getImagesPath()+"/"
                                 + imagefile + "." + secondary + "." + postfix;
      
      String preferedurl = GlobalConfiguration.getBaseUrl() + GlobalConfiguration.getRaAdminPath()
                          + GlobalConfiguration.getImagesPath()+"/"
                          + imagefile + "." + prefered + "." + postfix;
      
      String secondaryurl = GlobalConfiguration.getBaseUrl() + GlobalConfiguration.getRaAdminPath()
                          + GlobalConfiguration.getImagesPath()+"/"
                          + imagefile + "." + secondary + "." + postfix;
      
      String imageurl     = GlobalConfiguration.getBaseUrl()  + GlobalConfiguration.getRaAdminPath()
                          + GlobalConfiguration.getImagesPath()+"/"
                          + imagefile + "."  + postfix;
    
      if(new java.io.File(preferedfilename).exists())
        returnedurl = preferedurl;
      else{
        if(new java.io.File(secondaryfilename).exists())
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
    
    public void reloadGlobalConfiguration() throws RemoteException, NamingException {
      System.out.println("EjbcaWebBean reload");
      globalconfiguration = globaldataconfigurationdatahandler.loadGlobalConfiguration();
    }
    
    public void saveGlobalConfiguration() throws RemoteException{
      globaldataconfigurationdatahandler.saveGlobalConfiguration(globalconfiguration);       
    }
    
    public boolean existsUserPreference() throws RemoteException{
      return userspreferences.existsUserPreference(certificateserialnumber); 
    }
    
    public void addUserPreference(UserPreference up) throws UserExistsException, RemoteException{
      userspreferences.addUserPreference(certificateserialnumber,up);    
    }
    
      
    public void changeUserPreference(UserPreference up) throws UserDoesntExistException, RemoteException{
      userspreferences.changeUserPreference(certificateserialnumber,up);
    }
    
    // Private Methods
 
      
    // Private Fields. 
    private UsersPreferenceDataHandler userspreferences;
    private UserPreference currentuserpreference;
    private GlobalConfiguration globalconfiguration;
    private GlobalConfigurationDataHandler globaldataconfigurationdatahandler;
    private EjbcaAthorization authorize;
    private WebLanguages weblanguages;
    private WebLanguages usersweblanguage;
    private String usercommonname = "";
    private BigInteger certificateserialnumber;
    private X509Certificate[] certificates;
    private boolean initialized=false;
    
}
