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
import se.anatom.ejbca.util.query.Query;
import se.anatom.ejbca.util.query.IllegalQueryException;

/**
 * Administrates users in the database using UserData Entity Bean.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalUserAdminSessionBean.java,v 1.22 2002-07-28 23:27:47 herrvendil Exp $
 */
public class LocalUserAdminSessionBean extends BaseSessionBean  {

    /** The home interface of  GlobalConfiguration entity bean */
    private GlobalConfigurationDataLocalHome globalconfigurationhome = null;

    private UserDataLocalHome home = null;
    /** Columns in the database used in select */
    private final String USERDATA_COL = "username, subjectDN, subjectEmail, status, type, clearpassword, timeCreated, timeModified, profileId, certificateTypeId";
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
    
    /** Gets connection to Datasource used for manual SQL searches
     * @return Connection
     */
    private Connection getConnection() throws SQLException, NamingException {
        DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
        return ds.getConnection();
    } //getConnection
    
   /**
    * Implements IUserAdminSession::addUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void addUser(String username, String password, String dn, String email, int type, int profileid, int certificatetypeid) {
        debug(">addUser("+username+", password, "+dn+", "+email+", "+type+")");

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1=null;
            data1 = home.create(username, password, dn);
            if (email != null)
                data1.setSubjectEmail(email);
            data1.setType(type);
            data1.setProfileId(profileid);
            data1.setCertificateTypeId(certificatetypeid);
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
    public void changeUser(String username, String dn, String email, int type, int profileid, int certificatetypeid) {
        debug(">changeUser("+username+", "+dn+", "+email+", "+type+")");

        try {
            UserDataPK pk = new UserDataPK(username);
            UserDataLocal data1= home.findByPrimaryKey(pk);

            data1.setSubjectDN(dn);
            if (email != null)
                data1.setSubjectEmail(email);
            data1.setType(type);
            data1.setProfileId(profileid);
            data1.setCertificateTypeId(certificatetypeid);
            data1.setTimeModified((new java.util.Date()).getTime());
            
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
        data.setTimeModified((new java.util.Date()).getTime());        
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
            data.setTimeModified((new java.util.Date()).getTime());
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
            if (password == null){
                data.setClearPassword("");
                data.setTimeModified((new java.util.Date()).getTime());
            }    
            else{
                data.setOpenPassword(password);
                data.setTimeModified((new java.util.Date()).getTime());
            }    
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
        UserAdminData ret = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectEmail(), data.getStatus()
                                              , data.getType(), data.getProfileId(), data.getCertificateTypeId()
                                          , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified()) );
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
          returnval = new UserAdminData(data.getUsername(), data.getSubjectDN(), data.getSubjectEmail(), data.getStatus()
                                        , data.getType(), data.getProfileId(), data.getCertificateTypeId()
                                        , new java.util.Date(data.getTimeCreated()), new java.util.Date(data.getTimeModified()) );
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
            UserAdminData userData = new UserAdminData(user.getUsername(),user.getSubjectDN(),user.getSubjectEmail(),user.getStatus()
                                                       ,user.getType(), user.getProfileId(), user.getCertificateTypeId()
                                                       , new java.util.Date(user.getTimeCreated()), new java.util.Date(user.getTimeModified()) );
            userData.setPassword(user.getClearPassword());
            ret.add(userData);
        }
        debug("found "+ret.size()+" user(s) with status="+status);
        debug("<findAllUsersByStatus("+status+")");
        return ret;
    } // findAllUsersByStatus

    /**
    * Implements IUserAdminSession::findAllUsersWithLimit.
    */    
    public Collection findAllUsersWithLimit()  throws FinderException{
        debug(">findAllUsersWithLimit()");
        Collection users = home.findAll();
        Collection ret = new ArrayList();
        Iterator iter = users.iterator();
        while (iter.hasNext() && (ret.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT ))
        {
            UserDataLocal user = (UserDataLocal) iter.next();
            UserAdminData userData = new UserAdminData(user.getUsername(),user.getSubjectDN(),user.getSubjectEmail(),user.getStatus()
                                                       ,user.getType(), user.getProfileId(), user.getCertificateTypeId()
                                                       , new java.util.Date(user.getTimeCreated()), new java.util.Date(user.getTimeModified()) );
            userData.setPassword(user.getClearPassword());
            ret.add(userData);
        }         
        debug("<findAllUsersWithLimit()");  
        return ret;
    }

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
     * Method to execute a customized query on the ra user data. The parameter query should be a legal Query object.
     * 
     * @param query a number of statments compiled by query class to a SQL 'WHERE'-clause statment.
     * @return a collection of UserAdminData. Maximum size of Collection is defined i IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT
     * @throws IllegalQueryException when query parameters internal rules isn't fullfilled.
     * @see se.anatom.ejbca.util.query.Query 
     */
    public Collection query(Query query) throws IllegalQueryException{
        debug(">query()");
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList returnval = new ArrayList();
        
        // Check if query is legal.
        if(!query.isLegalQuery()) 
          throw new IllegalQueryException();
        try{
           // Construct SQL query.            
            con = getConnection();
            ps = con.prepareStatement("select " + USERDATA_COL + " from UserData where " + query.getQueryString());
            // Execute query.
            rs = ps.executeQuery();
            // Assemble result.            
            while(rs.next() && returnval.size() <= IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT){
              UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getInt(5)
                                               , rs.getInt(9), rs.getInt(10)
                                               , new java.util.Date(rs.getLong(7)), new java.util.Date(rs.getLong(8)));
              data.setPassword(rs.getString(6));
              returnval.add(data);
            }
            debug("<query()");  
            return returnval;
            
        }catch(Exception e){
          throw new EJBException(e);   
        }finally{
           try{
             if(rs != null) rs.close();
             if(ps != null) ps.close();
             if(con!= null) con.close();
           }catch(SQLException se){
              se.printStackTrace();   
           }
        }       
    } // query
    
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

