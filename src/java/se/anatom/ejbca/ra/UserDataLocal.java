package se.anatom.ejbca.ra;

import java.security.NoSuchAlgorithmException;

/**
 * For docs, see UserDataBean
 *
 * @version $Id: UserDataLocal.java,v 1.5 2003-01-12 17:16:28 anatom Exp $
 **/
public interface UserDataLocal extends javax.ejb.EJBLocalObject {

    // Constants for Status of user

    public static final int STATUS_NEW = 10;        // New user
    public static final int STATUS_FAILED = 11;     // Generation of user certificate failed
    public static final int STATUS_INITIALIZED = 20;// User has been initialized
    public static final int STATUS_INPROCESS = 30;  // Generation of user certificate in process
    public static final int STATUS_GENERATED = 40;  // A certificate has been generated for the user
    public static final int STATUS_REVOKED = 50;  // The user has been revoked and should not have any more certificates issued
    public static final int STATUS_HISTORICAL = 60; // The user is old and archived
    
    // public methods

    public String getUsername();
    public void setUsername(String username);
    public String getSubjectDN();
    public void setSubjectDN(String subjectDN);
    public String getSubjectAltName();
    public void setSubjectAltName(String subjectAltName);      
    public String getSubjectEmail();
    public void setSubjectEmail(String subjectEmail);
    public int getStatus();
    public void setStatus(int status);
    public int getType();
    public void setType(int type);
    public String getClearPassword();
    public void setClearPassword(String clearPassword);
    public String getPasswordHash();
    public void setPasswordHash(String passwordHash);
     
    public long getTimeCreated();    
    public long getTimeModified();  
    public void setTimeModified(long createtime);     
    public int getEndEntityProfileId();   
    public void setEndEntityProfileId(int endentityprofileid);  
    public int getCertificateProfileId();
    public void setCertificateProfileId(int certificateprofileid);      
    public int getTokenType();  
    public void setTokenType(int tokentype);   
    public int getHardTokenIssuerId();  
    public void setHardTokenIssuerId(int hardtokenissuerid);     

    public void setPassword(String password) throws  NoSuchAlgorithmException;
    public void setOpenPassword(String password) throws  NoSuchAlgorithmException;
    public boolean comparePassword(String password) throws NoSuchAlgorithmException;
}

