/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
 
package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import java.security.cert.X509CRL;

import javax.ejb.CreateException;
import javax.ejb.FinderException;


/**
 * For docs, see CRLDataBean
 */
public interface CRLDataHome extends javax.ejb.EJBHome {
    /**
     * DOCUMENT ME!
     *
     * @param incrl DOCUMENT ME!
     * @param number DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws CreateException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public CRLData create(X509CRL incrl, int number) throws CreateException, RemoteException;

    /**
     * DOCUMENT ME!
     *
     * @param pk DOCUMENT ME!
     *
     * @return DOCUMENT ME!
     *
     * @throws FinderException DOCUMENT ME!
     * @throws RemoteException DOCUMENT ME!
     */
    public CRLData findByPrimaryKey(CRLDataPK pk) throws FinderException, RemoteException;

    /**
     * Finds a CRL by the CRLNumber
     *
     * @param crlNumber the crlNUmberof the searched CRL
     * @return CRLDataLocal object
     */
    public CRLData findByIssuerDNAndCRLNumber(String issuerdn, int cRLNumber)
        throws FinderException, RemoteException;
}
