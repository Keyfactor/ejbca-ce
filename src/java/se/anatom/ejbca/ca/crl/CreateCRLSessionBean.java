package se.anatom.ejbca.ca.crl;

import java.util.*;
import java.io.*;

import java.rmi.*;
import javax.naming.*;
import javax.rmi.*;
import javax.ejb.*;

import java.security.cert.X509CRL;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.IJobRunnerSession;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.CertificateDataHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;

/**
 * Generates a new CRL by looking in the database for revoked certificates and
 * generating a CRL.
 *
 * @version $Id: CreateCRLSessionBean.java,v 1.1.1.1 2001-11-15 14:58:14 anatom Exp $
 */
public class CreateCRLSessionBean extends BaseSessionBean implements IJobRunnerSession {

    private Long crlperiod;

    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        // Get env variables and read in nessecary data
        crlperiod = (Long)lookup("java:comp/env/CRLPeriod", java.lang.Long.class);
        debug("crlperiod:" + crlperiod);
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
            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) 
lookup("CertificateStoreSession", ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote storeremote = storehome.create();
            // Find all revoked certificates
            String[] revcerts = storeremote.listRevokedCertificates();
            debug("Found "+revcerts.length+" revoked certificates.");

            // Go through them and create a CRL, at the same time archive expired certificates
            // TODO: Generate CRL is missing in BounceCastle
            CertificateDataHome home = (CertificateDataHome)lookup("CertificateData", CertificateDataHome.class);
            Date now = new Date();
            // crlperiod is hours = crlperiod*60*60*1000 milliseconds
            now.setTime(now.getTime() - (crlperiod.longValue() * 60 * 60 * 1000));
            Vector certs = new Vector();
            for (int i=0; i < revcerts.length; i++)
            {
                CertificateDataPK pk = new CertificateDataPK();
                pk.fp = revcerts[i];
                CertificateData data = home.findByPrimaryKey(pk);
                // We want to include certificates that was revoked after the last CRL was issued, but before this one
                // so the revoked certs are included in ONE CRL at least.
                if ( (data.getStatus() == CertificateData.CERT_REVOKED) &&
                    (data.getExpireDate().before(now)) )
                {
                        data.setStatus(CertificateData.CERT_ARCHIVED);
                } else
                {
                    if (data.getRevocationDate() == null)
                        data.setRevocationDate(new Date());
                    RevokedCertInfo certinfo = new RevokedCertInfo(data.getSerialNumber(), 
data.getRevocationDate(), data.getRevocationReason());
                    certs.add(certinfo);
                }
            }
            ISignSessionHome signhome = (ISignSessionHome) lookup("RSASignSession", ISignSessionHome.class);
            ISignSessionRemote signremote = signhome.create();
            X509CRL crl = signremote.createCRL(certs);

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


