
package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;

/**
 * For docs, see UserDataBean
 **/
public interface UserData extends javax.ejb.EJBObject {

    // Constants for Status of user
    public static final int STATUS_NEW = 10;        // New user
    public static final int STATUS_FAILED = 11;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20;// User has been initialized
    public static final int STATUS_INPROCESS = 30;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived

    // public methods
    public String getUsername() throws RemoteException;
    public void setUsername(String username) throws RemoteException;
    public boolean comparePassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public String getPasswordHash() throws RemoteException;
    public String getPassword() throws RemoteException;
    public void setPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public void setClearPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public String getSubjectDN() throws RemoteException;
    public void setSubjectDN(String dn) throws RemoteException;
    public String getSubjectEmail() throws RemoteException;
    public void setSubjectEmail(String email) throws RemoteException;
    public int getStatus() throws RemoteException;
    public void setStatus(int status) throws RemoteException;
    public int getType() throws RemoteException;
    public void setType(int type) throws RemoteException;

}
