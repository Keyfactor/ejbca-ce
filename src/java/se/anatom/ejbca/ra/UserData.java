
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
    public String getSubjectDN() throws RemoteException;
    public void setSubjectDN(String subjectDN) throws RemoteException;
    public String getSubjectEmail() throws RemoteException;
    public void setSubjectEmail(String subjectEmail) throws RemoteException;
    public int getStatus() throws RemoteException;
    public void setStatus(int status) throws RemoteException;
    public int getType() throws RemoteException;
    public void setType(int type) throws RemoteException;
    public String getClearPassword() throws RemoteException;
    public void setClearPassword(String clearPassword) throws RemoteException;
    public String getPasswordHash() throws RemoteException;
    public void setPasswordHash(String passwordHash) throws RemoteException;

    public void setPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public void setOpenPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public boolean comparePassword(String password) throws RemoteException, NoSuchAlgorithmException;
}
