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

/**
 * Administrates users in the database using UserData Entity Bean.
 * Uses JNDI name for datasource as defined in env 'Datasource' in ejb-jar.xml.
 *
 * @version $Id: LocalUserAdminSessionBean.java,v 1.12 2002-05-26 12:06:00 herrvendil Exp $
 */
public class LocalUserAdminSessionBean extends BaseSessionBean implements IUserAdminSession {

    private UserDataHome home = null;
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
        home = (UserDataHome) lookup("java:comp/env/ejb/UserData", UserDataHome.class);
        dataSource = (String)lookup("java:comp/env/DataSource", java.lang.String.class);
        debug("DataSource=" + dataSource);
        debug("<ejbCreate()");
    }

   /**
    * Implements IUserAdminSession::addUser.
    * Implements a mechanism that uses UserDataEntity Bean.
    */
    public void addUser(String username, String password, String dn, String email, int type) throws RemoteException {
        debug(">addUser("+username+", password, "+dn+", "+email+", "+type+")");

        try {
            UserDataPK pk = new UserDataPK();
            pk.username = username;

            UserData data1=null;
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
    * Implements IUserAdminSession::deleteUser.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void deleteUser(String username) throws RemoteException {
        debug(">deleteUser("+username+")");

        try {
            UserDataPK pk = new UserDataPK();
            pk.username = username;
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
    public void setUserStatus(String username, int status) throws FinderException, RemoteException {
        debug(">setUserStatus("+username+", "+status+")");
        // Find user
        UserDataPK pk = new UserDataPK();
        pk.username = username;
        UserData data = home.findByPrimaryKey(pk);
        data.setStatus(status);
        debug("<setUserStatus("+username+", "+status+")");
    } // setUserStatus

   /**
    * Implements IUserAdminSession::setPassword.
    * Implements a mechanism that uses UserData Entity Bean.
    */
    public void setPassword(String username, String password) throws FinderException, RemoteException {
        debug(">setPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK();
        pk.username = username;
        UserData data = home.findByPrimaryKey(pk);
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
    public void setClearTextPassword(String username, String password) throws FinderException, RemoteException {
        debug(">setClearTextPassword("+username+", hiddenpwd)");
        // Find user
        UserDataPK pk = new UserDataPK();
        pk.username = username;
        UserData data = home.findByPrimaryKey(pk);
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
    public UserAdminData findUser(String username) throws FinderException, RemoteException {
        debug(">findUser("+username+")");
        UserDataPK pk = new UserDataPK();
        pk.username = username;
        UserData data;
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

    public UserAdminData findUserBySubjectDN(String subjectdn) throws FinderException, RemoteException {
        debug(">findAllUsersBySubjectDN("+subjectdn+")");
        debug("Looking for users with subjectdn: " + subjectdn);
        String dn = CertTools.stringToBCDNString(subjectdn);
        UserAdminData returnval = null;
        Connection con = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        ArrayList ret = new ArrayList();
        try{
            con = getConnection();
            ps = con.prepareStatement("select "+USERDATA_COL+ " from UserData where subjectDN=?");
            ps.setString(1,dn);
            rs = ps.executeQuery();
            while(rs.next()){
                UserAdminData data = new UserAdminData(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4), rs.getInt(5));
                data.setPassword(rs.getString(6));
                ret.add( data );
            }
            debug("found "+ret.size()+" user(s) with subjectdn="+subjectdn);
            debug("<findAllUsersBySubjectDN("+subjectdn+")");
            if( ret.size() > 0 )
              returnval = (UserAdminData) ret.get(0);  
            return returnval;
        }
        catch (Exception e) {
            throw new EJBException(e.getMessage());
        }
        finally {
            try {
                if (rs != null) rs.close();
                if (ps != null) ps.close();
                if (con!= null) con.close();
            } catch(SQLException se) {
                se.printStackTrace();
            }
        }
    } // findUserBySubjectDN
 

    /**
    * Implements IUserAdminSession::findAllUsersByStatus.
    */
    public Collection findAllUsersByStatus(int status) throws FinderException, RemoteException {
        debug(">findAllUsersByStatus("+status+")");
        debug("Looking for users with status: " + status);
        Collection users = home.findByStatus(status);
        Collection ret = new ArrayList();
        Iterator iter = users.iterator();
        while (iter.hasNext())
        {
            UserData user = (UserData)iter.next();
            UserAdminData userData = new UserAdminData(user.getUsername(),user.getSubjectDN(),user.getSubjectEmail(),user.getStatus(),user.getType());
            userData.setPassword(user.getClearPassword());
            ret.add(userData);
        }
        debug("found "+ret.size()+" user(s) with status="+status);
        debug("<findAllUsersByStatus("+status+")");
        return ret;
    } // findAllUsersByStatus

    private Connection getConnection() throws SQLException, NamingException {
           DataSource ds = (DataSource)getInitialContext().lookup(dataSource);
           return ds.getConnection();
    } //getConnection

} // LocalUserAdminSessionBean

