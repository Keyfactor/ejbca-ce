package se.anatom.ejbca.ra;

import java.rmi.RemoteException;
import java.security.NoSuchAlgorithmException;



/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataRemote.java,v 1.3 2002-10-24 20:10:05 herrvendil Exp $
 **/

public interface UserDataRemote extends javax.ejb.EJBObject {

    // Constants for Status of user
    public static final int STATUS_NEW         = UserDataLocal.STATUS_NEW;        // New user
    public static final int STATUS_FAILED      = UserDataLocal.STATUS_FAILED;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = UserDataLocal.STATUS_INITIALIZED;// User has been initialized
    public static final int STATUS_INPROCESS   = UserDataLocal.STATUS_INPROCESS;  // Generation of user certificate in process
    public static final int STATUS_GENERATED   = UserDataLocal.STATUS_GENERATED;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED     = UserDataLocal.STATUS_REVOKED;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL  = UserDataLocal.STATUS_HISTORICAL; // The user is old and archived

    // public methods
    public String getUsername() throws RemoteException;
    public void setUsername(String username) throws RemoteException;
    public String getSubjectDN() throws RemoteException;
    public void setSubjectDN(String subjectDN) throws RemoteException;
    public String getSubjectAltName() throws RemoteException;
    public void setSubjectAltName(String subjectAltName) throws RemoteException;     
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
   
    public long getTimeCreated() throws RemoteException;    
    public long getTimeModified() throws RemoteException;  
    public void setTimeModified(long createtime) throws RemoteException;     
    public int getEndEntityProfileId() throws RemoteException;   
    public void setEndEntityProfileId(int endentityprofileid) throws RemoteException;  
    public int getCertificateProfileId() throws RemoteException;
    public void setCertificateProfileId(int certificateprofileid) throws RemoteException;      
    public int getTokenType() throws RemoteException;  
    public void setTokenType(int tokentype) throws RemoteException;   
    public int getHardTokenIssuerId() throws RemoteException;  
    public void setHardTokenIssuerId(int hardtokenissuerid) throws RemoteException;   

    public void setPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public void setOpenPassword(String password) throws RemoteException, NoSuchAlgorithmException;
    public boolean comparePassword(String password) throws RemoteException, NoSuchAlgorithmException;
}

