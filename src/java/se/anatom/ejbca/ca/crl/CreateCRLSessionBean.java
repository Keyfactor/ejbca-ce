package se.anatom.ejbca.ca.crl;

import java.util.*;
import java.io.*;

import java.rmi.*;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;
import java.math.BigInteger;
import java.security.cert.X509CRL;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.IJobRunnerSession;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSession;
import se.anatom.ejbca.ca.store.CertificateDataLocalHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataLocal;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSession;

/**
 * Generates a new CRL by looking in the database for revoked certificates and
 * generating a CRL.
 *
 * @version $Id: CreateCRLSessionBean.java,v 1.6 2002-05-26 08:50:17 anatom Exp $
 */
public class CreateCRLSessionBean extends BaseSessionBean implements IJobRunnerSession {

    private Long crlperiod;

    /** The home interface of Certificate store */
    private ICertificateStoreSessionHome storeHome = null;

    /** The home interface of Certificate entity bean */
    private CertificateDataLocalHome certHome = null;

    /** The home interface of the signing session */
    private ISignSessionHome signHome = null;

    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        // Get env variables and read in nessecary data
        crlperiod = (Long)lookup("java:comp/env/CRLPeriod", java.lang.Long.class);
        debug("crlperiod:" + crlperiod);
        storeHome = (ICertificateStoreSessionHome)lookup("java:comp/env/ejb/CertificateStoreSession", ICertificateStoreSessionHome.class);
        certHome = (CertificateDataLocalHome)lookup("java:comp/env/ejb/CertificateDataLocal");
        signHome = (ISignSessionHome) lookup("java:comp/env/ejb/SignSession", ISignSessionHome.class);
        debug("<ejbCreate()");
    }

   /**
    * Generates a new CRL by looking in the database for revoked certificates and
    * generating a CRL.
    *
    * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
    */
    public void run() throws RemoteException {
        debug(">run()");

        try {
            ICertificateStoreSession store = storeHome.create();
            // Find all revoked certificates
            Collection revcerts = store.listRevokedCertificates();
            debug("Found "+revcerts.size()+" revoked certificates.");

            // Go through them and create a CRL, at the same time archive expired certificates
            Date now = new Date();
            // crlperiod is hours = crlperiod*60*60*1000 milliseconds
            now.setTime(now.getTime() - (crlperiod.longValue() * 60 * 60 * 1000));
            Vector certs = new Vector();
            Iterator iter = revcerts.iterator();
            while (iter.hasNext()) {
                CertificateDataPK pk = new CertificateDataPK((String)iter.next());
                CertificateDataLocal data = certHome.findByPrimaryKey(pk);
                // We want to include certificates that was revoked after the last CRL was issued, but before this one
                // so the revoked certs are included in ONE CRL at least.
                if ( (data.getStatus() == CertificateData.CERT_REVOKED) &&
                    (data.getExpireDate() < now.getTime()) )
                {
                        data.setStatus(CertificateData.CERT_ARCHIVED);
                } else
                {
                    if (data.getRevocationDate() == -1)
                        data.setRevocationDate((new Date()).getTime());
                    RevokedCertInfo certinfo = new RevokedCertInfo(new BigInteger(data.getSerialNumber()),new Date(data.getRevocationDate()), data.getRevocationReason());
                    certs.add(certinfo);
                }
            }
            ISignSession sign = signHome.create();
            X509CRL crl = sign.createCRL(certs);

            //FileOutputStream fos = new FileOutputStream("srvtestcrl.der");
            //fos.write(crl.getEncoded());
            //fos.close();
        } catch (Exception e) {
            error("Failed to create CRL.", e);
            throw new EJBException(e);
        }
        debug("<run()");
    }
}


