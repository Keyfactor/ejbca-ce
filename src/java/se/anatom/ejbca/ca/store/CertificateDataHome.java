package se.anatom.ejbca.ca.store;

import java.rmi.RemoteException;
import javax.ejb.CreateException;
import javax.ejb.FinderException;

import java.security.cert.Certificate;
import java.util.Date;
import java.util.Collection;


/**
 * For docs, see CertificateDataBean
 **/
public interface CertificateDataHome extends javax.ejb.EJBHome {

    public CertificateData create(Certificate incert)
        throws CreateException, RemoteException;

    public CertificateData findByPrimaryKey(CertificateDataPK pk)
        throws FinderException, RemoteException;

    public Collection findByExpireDate(Date expireDate)
        throws FinderException, RemoteException;
}
