package se.anatom.ejbca.ra.raadmin;

import java.rmi.*;
import java.io.*;
import java.math.BigInteger;
import java.util.Date;
import java.util.Vector;
import java.util.Collection;
import java.util.TreeMap;
import java.util.Set;
import java.util.Iterator;
import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.webdist.webconfiguration.GlobalConfiguration;
import se.anatom.ejbca.webdist.webconfiguration.UserPreference;
import se.anatom.ejbca.webdist.rainterface.Profile;

/**
 * Stores data used by web server clients.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalRaAdminSessionBean.java,v 1.6 2002-07-04 13:03:18 herrvendil Exp $
 */
public class LocalRaAdminSessionBean extends BaseSessionBean  {

    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /** The home interface of  GlobalWebConfiguration entity bean */
    private GlobalWebConfigurationDataLocalHome globalconfigurationhome = null;

    /** The home interface of  UserPreferences entity bean */
    private UserPreferencesDataLocalHome userpreferenceshome=null;

    /** The home interface of  ProfileGroupData entity bean */
    private ProfileGroupDataLocalHome profilegroupdatahome=null;
    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate() throws CreateException {
        debug(">ejbCreate()");
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        globalconfigurationhome = (GlobalWebConfigurationDataLocalHome)lookup("java:comp/env/ejb/GlobalWebConfigurationDataLocal");      
        userpreferenceshome = (UserPreferencesDataLocalHome)lookup("java:comp/env/ejb/UserPreferencesDataLocal");
        profilegroupdatahome = (ProfileGroupDataLocalHome)lookup("java:comp/env/ejb/ProfileGroupDataLocal");
        debug("<ejbCreate()");
        
    }

    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection


    /** 
     * Loads the global configuration from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public GlobalConfiguration loadGlobalConfiguration()  {
        debug(">loadGlobalConfiguration()");
        GlobalConfiguration ret=null;
        try{
          GlobalWebConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey("0");
          if(gcdata!=null){
            ret = gcdata.getGlobalConfiguration();
          }
        }catch (javax.ejb.FinderException fe) {
             // Create new configuration
             ret = null;
        }
        debug("<loadGlobalConfiguration()");
        return ret;
    } //loadGlobalConfiguration

    /**
     * Saves global configuration to the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */

    public void saveGlobalConfiguration( GlobalConfiguration globalconfiguration)  {
        debug(">saveGlobalConfiguration()");
        String pk = "0";
        try {
          GlobalWebConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey(pk);  
          gcdata.setGlobalConfiguration(globalconfiguration);
        }catch (javax.ejb.FinderException fe) {
           // Global configuration doesn't yet exists. 
           try{ 
             GlobalWebConfigurationDataLocal data1= globalconfigurationhome.create(pk,globalconfiguration);     
           } catch(CreateException e){         
           }
        }         
        debug("<saveGlobalConfiguration()");
     } // saveGlobalConfiguration     
        
    
     /**

     * Finds the userpreference belonging to a certificate serialnumber. Returns null if user doesn't exists.

     */

    public UserPreference getUserPreference(BigInteger serialnumber){
        debug(">getUserPreference()");
        UserPreference ret =null;
        try {
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber);
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
            UserPreferencesDataLocal updata= userpreferenceshome.create(serialnumber,userpreference);
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
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber);
            userpreferenceshome.remove(serialnumber);
            try{ 
                UserPreferencesDataLocal updata2 = userpreferenceshome.findByPrimaryKey(serialnumber);  
            }  catch (javax.ejb.FinderException fe) {    
            }                  
            updata= userpreferenceshome.create(serialnumber,userpreference);
            try{ 
                UserPreferencesDataLocal updata3 = userpreferenceshome.findByPrimaryKey(serialnumber);
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
            UserPreferencesDataLocal updata = userpreferenceshome.findByPrimaryKey(serialnumber);
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
     * Adds a profile group to the database
     */

    public boolean addProfileGroup(String profilegroupname){
      boolean returnvalue=true;
      Iterator i=null;
      try{
        i = profilegroupdatahome.findAll().iterator();
      }catch(FinderException e){
          throw new EJBException(e);
      }
      while(i.hasNext()){
        if(profilegroupname.equals(((ProfileGroupDataLocal) i.next()).getProfileGroupName())){
          returnvalue=false;
        }
      }
      if(returnvalue){
        try{
          profilegroupdatahome.create(profilegroupname);
        }catch(Exception e){
           returnvalue = false;
        }
      }
      return returnvalue;
    } // addProfileGroup


    /**
     * Adds a profile group with the same content as the original profile,
     */
    public boolean cloneProfileGroup(String originalprofilegroupname, String newprofilegroupname){
      boolean returnvalue=true;
      Iterator i=null;
      try{
        i = profilegroupdatahome.findAll().iterator();
      }catch(FinderException e){
        throw new EJBException(e);
      }
      String groupname;

      while(i.hasNext()){ // Check if new group already exists.
        groupname = ((ProfileGroupDataLocal) i.next()).getProfileGroupName();
        if(newprofilegroupname.equals(groupname)){
          returnvalue=false;
        }
      }
      if(returnvalue){ // Clone group
        try{
          ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(originalprofilegroupname);
          TreeMap profiledatas = pgd.getProfiles();
          Set profilenames = profiledatas.keySet();
          ProfileGroupDataLocal newprofilegroup = profilegroupdatahome.create(newprofilegroupname);
          Iterator j = profilenames.iterator();
          while(j.hasNext()){
            String profilename = (String) j.next();
            Profile profile = (Profile) profiledatas.get(profilenames);
            newprofilegroup.addProfile(profilename, profile);
          }
        }catch(Exception e){
          returnvalue = false;
        }
      }
      return returnvalue;
    } // cloneProfileGroup

    /**
     * Removes a profile group from the database.
     */
    public void removeProfileGroup(String profilegroupname){
      try{
        profilegroupdatahome.remove(profilegroupname);
      }catch(Exception e){
        throw new EJBException(e);
      }
    } // removeProfileGroup

     /**
     * Renames a profile group
     */
    public boolean renameProfileGroup(String oldprofilegroupname, String newprofilegroupname){
      boolean returnvalue=true;
      Iterator i = null;
      try{
         i = profilegroupdatahome.findAll().iterator();
      }catch(FinderException e){
        throw new EJBException(e);
      }
      String groupname;

      while(i.hasNext()){ // Check if new group already exists.
        groupname = ((ProfileGroupDataLocal) i.next()).getProfileGroupName();
        if(newprofilegroupname.equals(groupname)){
          returnvalue=false;
        }
      }
      if(returnvalue){ // Create new group and delete old one.
        try{
          ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(oldprofilegroupname);
          TreeMap profiledatas = pgd.getProfiles();
          Set profilenames = profiledatas.keySet();
          ProfileGroupDataLocal newprofilegroup = profilegroupdatahome.create(newprofilegroupname);
          Iterator j = profilenames.iterator();
          while(j.hasNext()){
            String profilename = (String) j.next();
            Profile profile = (Profile) profiledatas.get(profilename);
            newprofilegroup.addProfile(profilename, profile);
          }
          profilegroupdatahome.remove(oldprofilegroupname);
        }catch(Exception e){
          returnvalue = false;
        }
      }
      return returnvalue;
    } // renameProfileGroup

    /**
     * Adds a profile to the database.
     */

    public boolean addProfile(String profilegroupname, String profilename, Profile profile){
       boolean returnval=true;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.addProfile(profilename,profile);
       }catch(FinderException e){
         returnval = false;
       }
       return returnval;
    } // addProfile

     /**
     * Adds a profile to a group with the same content as the original profile,
     */
    public boolean cloneProfile(String profilegroupname, String originalprofilename, String newprofilename){
       boolean returnval=true;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.cloneProfile(originalprofilename,newprofilename);
       }catch(FinderException e){
         returnval = false;
       }
       return returnval;
    } // cloneProfile

     /**
     * Removes a profile from the database.
     * @throws EJBException if a communication or other error occurs.
     */
    public void removeProfile(String profilegroupname, String profilename){
       try{
                System.out.println("localraadminSessionBean:removeProfile: 1");   
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
                System.out.println("localraadminSessionBean:removeProfile: 2"); 
         pgd.removeProfile(profilename);
       }catch(FinderException e){ }
        catch(EJBException e){ System.out.println("localraadminSessionBean:removeProfile: EJBException"); } 
    } // removeProfileGroup

     /**
     * Renames a profile
     */
    public boolean renameProfile(String profilegroupname, String oldprofilename, String newprofilename){
       boolean returnval=true;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.renameProfile(oldprofilename,newprofilename);
       }catch(Exception e){
         returnval = false;
       }
       return returnval;
    } // remameProfile

    /**
     * Updates profile data
     */

    public boolean changeProfile(String profilegroupname, String profilename, Profile profile){
       boolean returnval=true;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.changeProfile(profilename, profile);
       }catch(FinderException e){
         returnval = false;
       }
       return returnval;
    }// changeProfile

    /**
     * Retrives profile group names.
     */
    public Collection getProfileGroupNames(){
     Vector returnval = new Vector();
     Collection result = null;
     try{
       result = profilegroupdatahome.findAll();
       Iterator i = result.iterator();
       while(i.hasNext()){
          returnval.addElement(((ProfileGroupDataLocal) i.next()).getProfileGroupName());    
       }
     }catch(FinderException e){
        throw new EJBException(e);
     }
     return returnval;
    } // getProfileGroupNames
    /**
     * Retrives profile names sorted in specified group.
     */
    public Collection getProfileNames(String profilegroupname){
       Collection returnval=null;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.getProfileNames();
       }catch(FinderException e){
         throw new EJBException(e);
       }
       return returnval;
    } // getProfileNames
    /**
     * Retrives profiles sorted by name in specified group.
     */
    public TreeMap getProfiles(String profilegroupname){
       TreeMap returnval=null;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.getProfiles();
       }catch(FinderException e){
         throw new EJBException(e);
       }
       return returnval;
    } // getProfiles
    
    /**
     * Retrives a named profile.
     */
    public Profile getProfile(String profilegroupname, String profilename){
       Profile returnval=null;
       try{
         ProfileGroupDataLocal pgd = profilegroupdatahome.findByPrimaryKey(profilegroupname);
         returnval = pgd.getProfile(profilename);
       }catch(FinderException e){
         throw new EJBException(e);
       }
       return returnval;
    } //  getProfile

    /**
     * Retrives the numbers of profilegroups in the database.
     */    
    public int getNumberOfProfileGroups(){
     int returnval=0;
     Collection result;
     try{   
       result = profilegroupdatahome.findAll();     
       returnval = result.size();
     }catch(FinderException e){}
     return returnval;
    }
    
     /**
     * Retrives the numbers of profiles in the profilegroup.
     */    
    public int getNumberOfProfiles(String profilegroupname){
      return getProfileNames(profilegroupname).size();  
    }   
    
} // LocalRaAdminSessionBean

