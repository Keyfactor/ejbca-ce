package se.anatom.ejbca.ca.store;

import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.security.cert.X509CRL;

/**
 * For docs, see CRLDataBean
 **/
public interface CRLDataLocalHome extends javax.ejb.EJBLocalHome {

    public CRLDataLocal create(X509CRL incrl, int number)
        throws CreateException;

    public CRLDataLocal findByPrimaryKey(CRLDataPK pk)
        throws FinderException;
    /** Finds a CRL by the CRLNumber
     * @param crlNumber the crlNUmberof the searched CRL
     * @return CRLDataLocal object
     */
    public CRLDataLocal findByCRLNumber(int cRLNumber)
        throws FinderException;
}
