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
}
