package se.anatom.ejbca.ra.raadmin;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;
import java.util.Collection;
import java.util.Collections;
import java.util.TreeMap;
import java.util.Set;
import java.util.Iterator;
import java.util.Random;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import org.apache.log4j.*;
import RegularExpression.RE;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.ra.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.UserPreference;
import se.anatom.ejbca.ra.raadmin.Profile;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalRaAdminSessionBean.java,v 1.11 2002-08-27 12:41:07 herrvendil Exp $
 */
public class LocalRaAdminSessionBean extends BaseSessionBean  {

    private static Category cat = Category.getInstance(LocalRaAdminSessionBean.class.getName());

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  UserPreferences entity bean */
    private UserPreferencesDataLocalHome userpreferenceshome=null;

    /** The home interface of  ProfileData entity bean */
    private ProfileDataLocalHome profiledatahome=null;
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public final static String EMPTY_PROFILE   = "EMPTY"; 
    public final static int    EMPTY_PROFILEID = 1;
    
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);

        userpreferenceshome = (UserPreferencesDataLocalHome)lookup("java:comp/env/ejb/UserPreferencesDataLocal", UserPreferencesDataLocalHome.class);
        profiledatahome = (ProfileDataLocalHome)lookup("java:comp/env/ejb/ProfileDataLocal", ProfileDataLocalHome.class);
        debug("<ejbCreate()");
               
        try{
          profiledatahome.findByProfileName(EMPTY_PROFILE);
        }catch(FinderException e){
          try{  
            profiledatahome.create(new Integer(EMPTY_PROFILEID),EMPTY_PROFILE,new Profile());
          }catch(Exception f){}  
        }

    }


    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    

     /**
     * Finds the userpreference belonging to a certificate serialnumber. Returns null if user doesn't exists.
     */

    public UserPreference getUserPreference(BigInteger serialnumber){
        debug(">getUserPreference()");
        UserPreference ret =null;
        try {
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber.toString());
            ret = updata.getUserPreference();
        } catch (javax.ejb.FinderException fe) {
             // Create new configuration
             ret=null;
        } catch(Exception e){
          throw new EJBException(e);
        }
        debug("<getUserPreference()");
        return ret;
    } // getUserPreference

    /**
     * Adds a user preference to the database. Returns false if user already exists.
     */

    public boolean addUserPreference(BigInteger serialnumber, UserPreference userpreference){
        debug(">addUserPreference(serial : " + serialnumber + ")");
        boolean ret = false;
        try {
            UserPreferencesDataLocal updata= userpreferenceshome.create(serialnumber.toString(),userpreference);
            ret = true;
        }
        catch (Exception e) {
          ret = false;
        }
        debug("<addUserPreference()");
        return ret;
    } // addUserPreference

    /**
     * Changes the userpreference in the database. Returns false if user doesn't exists.
     */

    public boolean changeUserPreference(BigInteger serialnumber, UserPreference userpreference){
       debug(">changeUserPreference(serial : " + serialnumber + ")");
       boolean ret = false;
        try {
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber.toString());
            userpreferenceshome.remove(serialnumber.toString());
            try{
                UserPreferencesDataLocal updata2 = userpreferenceshome.findByPrimaryKey(serialnumber.toString());
            }  catch (javax.ejb.FinderException fe) {
            }
            updata= userpreferenceshome.create(serialnumber.toString(),userpreference);
            try{
                UserPreferencesDataLocal updata3 = userpreferenceshome.findByPrimaryKey(serialnumber.toString());
            }  catch (javax.ejb.FinderException fe) {
            }
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
        } catch(Exception e){
          throw new EJBException(e);
        }
        debug("<changeUserPreference()");
        return ret;
    } // changeUserPreference

    /**
     * Checks if a userpreference exists in the database.
     */

    public boolean existsUserPreference(BigInteger serialnumber){
       debug(">existsUserPreference(serial : " + serialnumber + ")");
       boolean ret = false;
        try {
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber.toString());
            ret = true;
        } catch (javax.ejb.FinderException fe) {
             ret=false;
        } catch(Exception e){
          throw new EJBException(e);
        }
        debug("<existsUserPreference()");
        return ret;
    }// existsUserPreference

    /**
     * Adds a profile to the database.
     */

    public boolean addProfile(String profilename, Profile profile){
       boolean returnval=false;
       try{
          profiledatahome.findByProfileName(profilename);
       }catch(FinderException e){
         try{  
           profiledatahome.create(findFreeProfileId(),profilename,profile);
           returnval = true;
         }catch(Exception f){}  
       }
       return returnval;
    } // addProfile

     /**
     * Adds a profile to a group with the same content as the original profile.
     */
    public boolean cloneProfile(String originalprofilename, String newprofilename){
       Profile profile = null; 
       boolean returnval = false;
       try{
         ProfileDataLocal pdl = profiledatahome.findByProfileName(originalprofilename);
         profile = (Profile) pdl.getProfile().clone();
         
         returnval = addProfile(newprofilename, profile);
       }catch(FinderException e){}
        catch(CloneNotSupportedException f){}
       
       return returnval;
    } // cloneProfile

     /**
     * Removes a profile from the database.
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeProfile(String profilename) {
      try{
        ProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);  
        pdl.remove();
      }catch(Exception e){}  
    } // removeProfile

     /**
     * Renames a profile
     */
    public boolean renameProfile(String oldprofilename, String newprofilename){
       boolean returnvalue = false;   
       try{
          profiledatahome.findByProfileName(newprofilename); 
       }catch(FinderException e){
         try{
           ProfileDataLocal pdl = profiledatahome.findByProfileName(oldprofilename);   
           pdl.setProfileName(newprofilename);
           returnvalue = true;
         }catch(FinderException f){}
       }  
       return returnvalue;   
    } // remameProfile

    /**
     * Updates profile data
     */

    public boolean changeProfile(String profilename, Profile profile){
       boolean returnvalue = false;
       
       try{
         ProfileDataLocal pdl = profiledatahome.findByProfileName(profilename);   
         pdl.setProfile(profile);
         returnvalue = true;
       }catch(FinderException e){}  
       return returnvalue;   
    }// changeProfile

    /**
     * Retrives profile names sorted.
     */
    public Collection getProfileNames(){
      Vector returnval = new Vector();
      Collection result = null;
      try{
        result = profiledatahome.findAll();
        if(result.size()>0){ 
          Iterator i = result.iterator();
          while(i.hasNext()){
            returnval.add(((ProfileDataLocal) i.next()).getProfileName());
          }
        }
        Collections.sort(returnval);
      }catch(Exception e){}
      return returnval;      
    } // getProfileNames
    
    /**
     * Retrives profiles sorted by name.
     */
    public TreeMap getProfiles(){
      TreeMap returnval = new TreeMap();
      Collection result = null;
      try{
        result = profiledatahome.findAll();
        if(result.size()>0){
          returnval = new TreeMap();  
          Iterator i = result.iterator();
          while(i.hasNext()){
            ProfileDataLocal pdl = (ProfileDataLocal) i.next();
            returnval.put(pdl.getProfileName(),pdl.getProfile());
          }
        }
      }catch(FinderException e){}
      return returnval;    
    } // getProfiles

    /**
     * Retrives a named profile.
     */
    public Profile getProfile(String profilename){
       Profile returnval=null;
       try{
         returnval = (profiledatahome.findByProfileName(profilename)).getProfile();
       }catch(FinderException e){
         throw new EJBException(e);
       }
       return returnval;  
    } //  getProfile

     /**
     * Finds a profile by id.
     */       
    public Profile getProfile(int id){
       Profile returnval=null;
       try{
         returnval = (profiledatahome.findByPrimaryKey(new Integer(id))).getProfile();
       }catch(FinderException e){
         throw new EJBException(e);
       }
       return returnval;        
    } // getProfile
    
     /**
     * Retrives the numbers of profiles.
     */
    public int getNumberOfProfiles(){
      int returnval =0;
      try{
        returnval = (profiledatahome.findAll()).size();
      }catch(FinderException e){}
      
      return returnval;                
    }
     
     /**
     * Returns a profiles id, given it's profilename
     *
     * @return the id or 0 if profile cannot be found.
     */   
    public int getProfileId(String profilename){
      int returnval = 0;  
      try{  
        Integer id = (profiledatahome.findByProfileName(profilename)).getId();
        returnval = id.intValue();
      }catch(FinderException e){}
      
      return returnval;        
    } // getProfileId
    
     /**
     * Returns a profiles name given it's id. 
     *
     * @return profilename or null if profile id doesn't exists.
     */    
    public String getProfileName(int id){
      String returnval = null;  
      try{  
        returnval = (profiledatahome.findByPrimaryKey(new Integer(id))).getProfileName();
      }catch(FinderException e){}
      
      return returnval;
    } // getProfileName
    
     /** 
     * Method to check if a certificatetype exists in any of the profiles. Used to avoid desyncronization of profile data.
     *
     * @param certificatetypeid the certificatetype id to search for.
     * @return true if certificatetype exists in any of the accessrules.
     */
    
    public boolean existsCertificateTypeInProfiles(int certificatetypeid){
      String[] availablecerttypes=null;
      boolean exists = false;
      try{
        Collection result = profiledatahome.findAll();
        Iterator i = result.iterator();
        while(i.hasNext() && !exists){
          availablecerttypes = new RE(Profile.SPLITCHAR, false).split(((ProfileDataLocal) i.next()).getProfile().getValue(Profile.AVAILABLECERTTYPES));
          for(int j=0; j < availablecerttypes.length; j++){
            if(Integer.parseInt(availablecerttypes[j]) == certificatetypeid){
              exists=true;
              break;
            };
          }
        }
      }catch(Exception e){}
      
      return exists;
    }
    
    // Private methods
    
    private Integer findFreeProfileId(){
      int id = (new Random((new Date()).getTime())).nextInt();
      boolean foundfree = false;
      
      while(!foundfree){
        try{  
          if(id > 1)  
            profiledatahome.findByPrimaryKey(new Integer(id));
          id++;
        }catch(FinderException e){
           foundfree = true;   
        }
      }      
      return new Integer(id);
    } // findFreeProfileId
    
} // LocalRaAdminSessionBean

