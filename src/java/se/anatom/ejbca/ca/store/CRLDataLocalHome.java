package se.anatom.ejbca.ca.store;

import java.security.cert.X509CRL;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see CRLDataBean
 */
public interface CRLDataLocalHome extends javax.ejb.EJBLocalHome {
    /**
     * DOCUMENT ME!
     *
     * @param incrl DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     */
    public CRLDataLocal create(X509CRL incrl, int number)
        throws CreateException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     */
    public CRLDataLocal findByPrimaryKey(CRLDataPK pk)
        throws FinderException;

    /**
     * Finds a CRL by the CRLNumber
     *
     * @param crlNumber the crlNUmberof the searched CRL
     *
     * @return CRLDataLocal object
     */
    public CRLDataLocal findByCRLNumber(int cRLNumber)
        throws FinderException;
}
