package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.security.cert.X509CRL;

/**
 * For docs, see CRLDataBean
 **/
public interface CRLDataHome extends javax.ejb.EJBHome {

    public CRLData create(X509CRL incrl, int number)
        throws CreateException, RemoteException;

    public CRLData findByPrimaryKey(CRLDataPK pk)
        throws FinderException, RemoteException;
    /** Finds a CRL by the CRLNumber
     * @param crlNumber the crlNUmberof the searched CRL
     * @return CRLData object
     */
    public CRLData findByCRLNumber(int cRLNumber)
        throws FinderException, RemoteException;
}
