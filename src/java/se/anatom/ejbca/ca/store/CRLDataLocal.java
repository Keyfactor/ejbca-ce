
package se.anatom.ejbca.ca.store;

import java.security.cert.X509CRL;
import java.util.Date;

import java.rmi.RemoteException;

/**
 * For docs, see CRLDataBean
 **/
public interface CRLDataLocal extends javax.ejb.EJBLocalObject {

    // public methods
    public int getCRLNumber();
    public void setCRLNumber(int cRLNumber);
    public String getIssuerDN();
    public String getFingerprint();
    public void setFingerprint(String fingerprint);
    public String getCAFingerprint();
    public void setCAFingerprint(String cAFingerprint);
    public long getThisUpdate();
    public void setThisUpdate(long thisUpdate);
    public long getNextUpdate();
    public void setNextUpdate(long nextUpdate);
    public String getBase64Crl();
    public void setBase64Crl(String base64Crl);

    public X509CRL getCRL();
    public void setCRL(X509CRL crl);
    public void setIssuer(String dn);
    public void setThisUpdate(Date thisUpdate);
    public void setNextUpdate(Date nextUpdate);
}
