
package se.anatom.ejbca.ca.store;

import java.security.cert.X509CRL;
import java.util.Date;

import java.rmi.RemoteException;

/**
 * For docs, see CRLDataBean
 **/
public interface CRLData extends javax.ejb.EJBObject {

    // Constants for Revocation reason
    public static int REASON_UNUSED =               0x0;    // Unknown reason for revocation (reason unused).
    public static int REASON_KEYCOMPROMISE =        0x1;    // Private key has been compromised.
    public static int REASON_CACOMPROMISE =         0x2;    // CAs private key has been compromised.
    public static int REASON_AFFILIATIONCHANGED =   0x4;    // Users affiliation changed.
    public static int REASON_CESSATIONOFOPERATION = 0x8;    // Cessation Of Operation.
    public static int REASON_CERTIFICATEHOLD =      0x10;    // Certificate is revoced temporarily.

    // public methods
    public X509CRL getCRL() throws RemoteException;
    public void setCRL(X509CRL crl) throws RemoteException;
    public int getCRLNumber() throws RemoteException;
    public void setCRLNumber(int number) throws RemoteException;
    public String getIssuer() throws RemoteException;
    public void setIssuer(String dn) throws RemoteException;
    public String getFingerprint() throws RemoteException;
    public void setFingerprint(String fp) throws RemoteException;
    public String getCAFingerprint() throws RemoteException;
    public void setCAFingerprint(String cafp) throws RemoteException;
    public Date getThisUpdate() throws RemoteException;
    public void setThisUpdate(Date date) throws RemoteException;
    public Date getNextUpdate() throws RemoteException;
    public void setNextUpdate(Date date) throws RemoteException;
}
