
package se.anatom.ejbca.ca.store;

import java.security.cert.X509CRL;
import java.util.Date;

import java.rmi.RemoteException;

/**
 * For docs, see CRLDataBean
 **/
public interface CRLData extends javax.ejb.EJBObject {

    // public methods
    public int getCRLNumber() throws RemoteException;
    public void setCRLNumber(int cRLNumber) throws RemoteException;
    public String getIssuerDN() throws RemoteException;
    public String getFingerprint() throws RemoteException;
    public void setFingerprint(String fingerprint) throws RemoteException;
    public String getCAFingerprint() throws RemoteException;
    public void setCAFingerprint(String cAFingerprint) throws RemoteException;
    public long getThisUpdate() throws RemoteException;
    public void setThisUpdate(long thisUpdate) throws RemoteException;
    public long getNextUpdate() throws RemoteException;
    public void setNextUpdate(long nextUpdate) throws RemoteException;
    public String getBase64Crl() throws RemoteException;
    public void setBase64Crl(String base64Crl) throws RemoteException;

    public X509CRL getCRL() throws RemoteException;
    public void setCRL(X509CRL crl) throws RemoteException;
    public void setIssuer(String dn) throws RemoteException;
    public void setThisUpdate(Date thisUpdate) throws RemoteException;
    public void setNextUpdate(Date nextUpdate) throws RemoteException;
}
