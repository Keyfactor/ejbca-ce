
package se.anatom.ejbca.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.Date;

import java.rmi.RemoteException;

/**
 * For docs, see CertificateDataBean
 **/
public interface CertificateData extends javax.ejb.EJBObject {

    // Constants for Status of certificate
    public static int CERT_UNASSIGNED =      0;     // Certificate doesn't belong to anyone
    public static int CERT_INACTIVE =        10;    // Assigned, but not yet active
    public static int CERT_ACTIVE =          20;    // Certificate is active and assigned
    public static int CERT_TEMP_REVOKED =    30;    // Certificate is temporarily blocked (reversible)
    public static int CERT_REVOKED =         40;    // Certificate is permanently blocked (terminated)
    public static int CERT_EXPIRED =         50;    // Certificate is expired
    public static int CERT_ARCHIVED =        60;   // Certificate is expired and kept for archive purpose

    // public methods
    public Certificate getCertificate() throws RemoteException;
    public void setCertificate(Certificate cert) throws RemoteException;
    public String getSubject() throws RemoteException;
    public void setSubject(String dn) throws RemoteException;
    public String getIssuer() throws RemoteException;
    public void setIssuer(String dn) throws RemoteException;
    public BigInteger getSerialNumber() throws RemoteException;
    public void setSerialNumber(BigInteger serno) throws RemoteException;
    public String getFingerprint() throws RemoteException;
    public void setFingerprint(String fp) throws RemoteException;
    public int getStatus() throws RemoteException;
    public void setStatus(int status) throws RemoteException;
    public int getType() throws RemoteException;
    public void setType(int type) throws RemoteException;
    public String getCAFingerprint() throws RemoteException;
    public void setCAFingerprint(String cafp) throws RemoteException;
    public Date getExpireDate() throws RemoteException;
    public void setExpireDate(Date date) throws RemoteException;
    public Date getRevocationDate() throws RemoteException;
    public void setRevocationDate(Date date) throws RemoteException;
    public int getRevocationReason() throws RemoteException;
    public void setRevocationReason(int reason) throws RemoteException;

}
