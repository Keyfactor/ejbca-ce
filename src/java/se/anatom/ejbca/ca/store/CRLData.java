package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;

import java.security.cert.X509CRL;

import java.util.Date;


/**
 * For docs, see CRLDataBean
 */
public interface CRLData extends javax.ejb.EJBObject {
    // public methods
    public int getCRLNumber() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param cRLNumber DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setCRLNumber(int cRLNumber) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getIssuerDN() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getFingerprint() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param fingerprint DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setFingerprint(String fingerprint) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getCAFingerprint() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param cAFingerprint DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setCAFingerprint(String cAFingerprint)
        throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public long getThisUpdate() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param thisUpdate DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setThisUpdate(long thisUpdate) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public long getNextUpdate() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param nextUpdate DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setNextUpdate(long nextUpdate) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public String getBase64Crl() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param base64Crl DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setBase64Crl(String base64Crl) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public X509CRL getCRL() throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param crl DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setCRL(X509CRL crl) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param dn DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setIssuer(String dn) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param thisUpdate DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setThisUpdate(Date thisUpdate) throws RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param nextUpdate DOCUMENT ME!
     *
     * @throws RemoteException DOCUMENT ME!
     */
    public void setNextUpdate(Date nextUpdate) throws RemoteException;
}
