package se.anatom.ejbca.ra;

import java.io.*;
import java.util.*;

import java.sql.*;
import javax.sql.DataSource;
import javax.naming.*;
import java.rmi.*;
import javax.rmi.*;
import javax.ejb.*;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.ra.GlobalConfiguration;

/**
 * Administrates users in the database using UserData Entity Bean.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalUserAdminSessionBean.java,v 1.21 2002-07-26 09:26:39 anatom Exp $
 */
public class LocalUserAdminSessionBean extends BaseSessionBean  {

    /** The home interface of  GlobalConfiguration entity bean */
    private GlobalConfigurationDataLocalHome globalconfigurationhome = null;

    private UserDataLocalHome home = null;
    /** Columns in the database used in select */
    private final String USERDATA_COL = "username, subjectDN, subjectEmail, status, type, clearpassword";
    /** Var holding JNDI name of datasource */
    private String dataSource = "java:/DefaultDS";

    /**
     * Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        home = (UserDataLocalHome) lookup("java:comp/env/ejb/UserDataLocal", UserDataLocalHome.class);
        globalconfigurationhome = (GlobalConfigurationDataLocalHome)lookup("java:comp/env/ejb/GlobalConfigurationDataLocal", GlobalConfigurationDataLocalHome.class);
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        debug("<ejbCreate()");
    }

   /**
    * Implements IUserAdminSession::addUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void addUser(String username, String password, String dn, String email, int type) {
        debug(">addUser("+username+", password, "+dn+", "+email+", "+type+")");

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1=null;
            data1 = home.create(username, password, dn);
            if (email != null)
                data1.setSubjectEmail(email);
            data1.setType(type);
            info("Added user "+pk.username);
        }
        catch (Exception e) {
            error("Add user failed.", e);
            throw new EJBException(e.getMessage());
        }
        debug("<addUser("+username+", password, "+dn+", "+email+", "+type+")");
    } // addUser

   /**
    * Implements IUserAdminSession::changeUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void changeUser(String username, String dn, String email, int type) {
        debug(">changeUser("+username+", "+dn+", "+email+", "+type+")");

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1= home.findByPrimaryKey(pk);

            data1.setSubjectDN(dn);
            if (email != null)
                data1.setSubjectEmail(email);
            data1.setType(type);
            info("Changed user "+pk.username);
        }
        catch (Exception e) {
            error("change user failed.", e);
            throw new EJBException(e.getMessage());
        }
        debug("<changeUser("+username+", password, "+dn+", "+email+", "+type+")");
    } // changeUser


   /**
    * Implements IUserAdminSession::deleteUser.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void deleteUser(String username) {
        debug(">deleteUser("+username+")");

        try {
            UserDataPK pk = new UserDataPK(username);
            home.remove(pk);
            info("Deleted user "+pk.username);
        }
        catch (Exception e) {
            error("Delete user failed.", e);
            throw new EJBException(e.getMessage());
        }
        debug("<deleteUser("+username+")");
    } // deleteUser

   /**
    * Implements IUserAdminSession::setUserStatus.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setUserStatus(String username, int status) throws FinderException{
        debug(">setUserStatus("+username+", "+status+")");
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        data.setStatus(status);
        debug("<setUserStatus("+username+", "+status+")");
    } // setUserStatus

   /**
    * Implements IUserAdminSession::setPassword.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setPassword(String username, String password) throws FinderException{
        debug(">setPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        try {
            data.setPassword(password);
        } catch (java.security.NoSuchAlgorithmException nsae)
        {
            error("NoSuchAlgorithmException while setting password for user "+username);
            throw new EJBException(nsae);
        }
        debug("<setPassword("+username+", hiddenpwd)");
    } // setPassword

   /**
    * Implements IUserAdminSession::setClearTextPassword.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setClearTextPassword(String username, String password) throws FinderException{
        debug(">setClearTextPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data = home.findByPrimaryKey(pk);
        try {
            if (password == null)
                data.setClearPassword(null);
            else
                data.setOpenPassword(password);
        } catch (java.security.NoSuchAlgorithmException nsae)
        {
            error("NoSuchAlgorithmException while setting password for user "+username);
            throw new EJBException(nsae);
        }
        debug("<setClearTextPassword("+username+", hiddenpwd)");
    } // setClearTextPassword

    /**
    * Implements IUserAdminSession::findUser.
    */
    public UserAdminData findUser(String username) throws FinderException {
        debug(">findUser("+username+")");
        UserDataPK pk = new UserDataPK(username);
        UserDataLocal data;
        try {
            data = home.findByPrimaryKey(pk);
        } catch (ObjectNotFoundException oe) {
            return null;
        }
        UserAdminData ret = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectEmail(), data.getStatus(), data.getType());
        ret.setPassword(data.getClearPassword());
        debug("<findUser("+username+")");
        return ret;
    } // findUser

   /**
    * Implements IUserAdminSession::findUserBySubjectDN.
    */
    public UserAdminData findUserBySubjectDN(String subjectdn) {
        debug(">findUserBySubjectDN("+subjectdn+")");
        String dn = CertTools.stringToBCDNString(subjectdn);
        debug("Looking for users with subjectdn: " + dn);
        UserAdminData returnval = null;

        UserDataLocal data = null;
        try{
          data = home.findBySubjectDN(dn);
        } catch( FinderException e) {
            cat.error("Cannot find user with DN='"+dn+"'");
        }
        if(data != null){
          returnval = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectEmail(), data.getStatus(), data.getType());
          returnval.setPassword(data.getClearPassword());
        }
        debug("<findUserBySubjectDN("+subjectdn+")");
        return returnval;
    } // findUserBySubjectDN

    /**
    * Implements IUserAdminSession::findAllUsersByStatus.
    */
    public Collection findAllUsersByStatus(int status) throws FinderException {
        debug(">findAllUsersByStatus("+status+")");
        debug("Looking for users with status: " + status);
        Collection users = home.findByStatus(status);
        Collection ret = new ArrayList();
        Iterator iter = users.iterator();
        while (iter.hasNext())
        {
            UserDataLocal user = (UserDataLocal) iter.next();
            UserAdminData userData = new UserAdminData(user.getUsername(),user.getSubjectDN(),user.getSubjectEmail(),user.getStatus(),user.getType());
            userData.setPassword(user.getClearPassword());
            ret.add(userData);
        }
        debug("found "+ret.size()+" user(s) with status="+status);
        debug("<findAllUsersByStatus("+status+")");
        return ret;
    } // findAllUsersByStatus


   /**
    * Implements IUserAdminSession::startExternalService.
    */
    public void startExternalService( String[] args ) {
        debug(">startService()");
        try {
            final int registryPortRMI =
                ((Integer)lookup("java:comp/env/registryPortRMI",
                                 java.lang.Integer.class)).intValue();
            final int startPortRMI =
                ((Integer)lookup("java:comp/env/startPortRMI",
                                 java.lang.Integer.class)).intValue();
            final String keyFileName =
                (String)lookup("java:comp/env/keyStoreFileName",
                                 java.lang.String.class);
            final String keyStorePassword =
                (String)lookup("java:comp/env/keyStorePassword",
                                 java.lang.String.class);
            RMIFactory rmiFactory = (RMIFactory)Class.forName(
                (String)lookup("java:comp/env/RMIFactory",
                               java.lang.String.class)
                ).newInstance();
            rmiFactory.startConnection(registryPortRMI, startPortRMI,
                keyFileName, keyStorePassword, args );
            debug(">startService()");
        } catch( Exception e ) {
            error("Lyckades inte starta extern service.", e);
            throw new EJBException("Error starting external service", e);
        }
    } // startExternalService

     /**
     * Loads the global configuration from the database.
     *
     * @throws EJBException if a communication or other error occurs.
     */
    public GlobalConfiguration loadGlobalConfiguration()  {
        debug(">loadGlobalConfiguration()");
        GlobalConfiguration ret=null;
        try{
          GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey("0");
          if(gcdata!=null){
            ret = gcdata.getGlobalConfiguration();
          }
        }catch (javax.ejb.FinderException fe) {
             // Create new configuration
             ret = new GlobalConfiguration();
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
          GlobalConfigurationDataLocal gcdata = globalconfigurationhome.findByPrimaryKey(pk);
          gcdata.setGlobalConfiguration(globalconfiguration);
        }catch (javax.ejb.FinderException fe) {
           // Global configuration doesn't yet exists.
           try{
             GlobalConfigurationDataLocal data1= globalconfigurationhome.create(pk,globalconfiguration);
           } catch(CreateException e){
           }
        }
        debug("<saveGlobalConfiguration()");
     } // saveGlobalConfiguration

} // LocalUserAdminSessionBean

