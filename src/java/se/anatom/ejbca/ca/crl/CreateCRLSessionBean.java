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
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.CertificateDataLocalHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataLocal;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.crl.RevokedCertInfo;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionRemote;
import se.anatom.ejbca.log.ILogSessionHome;
import se.anatom.ejbca.log.LogEntry;

/**
 * Generates a new CRL by looking in the database for revoked certificates and
 * generating a CRL.
 *
 * @version $Id: CreateCRLSessionBean.java,v 1.9 2002-09-12 18:14:16 herrvendil Exp $
 */
public class CreateCRLSessionBean extends BaseSessionBean implements IJobRunnerSession {

    private Long crlperiod;

    /** The home interface of Certificate store */
    private ICertificateStoreSessionLocalHome storeHome = null;

    /** The home interface of Certificate entity bean */
    private CertificateDataLocalHome certHome = null;

    /** The home interface of the signing session */
    private ISignSessionLocalHome signHome = null;
    
    /** The remote interface of the log session bean */
    private ILogSessionRemote logsession;        
    
    private Admin admin = null;

    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate (Admin administrator) throws CreateException {
        debug(">ejbCreate()");
        // Get env variables and read in nessecary data
        crlperiod = (Long)lookup("java:comp/env/CRLPeriod", java.lang.Long.class);
        debug("crlperiod:" + crlperiod);
        storeHome = (ICertificateStoreSessionLocalHome)lookup("java:comp/env/ejb/CertificateStoreSessionLocal");
        certHome = (CertificateDataLocalHome)lookup("java:comp/env/ejb/CertificateDataLocal");
        signHome = (ISignSessionLocalHome)lookup("java:comp/env/ejb/SignSessionLocal");
        
        try{
          this.admin = administrator;  
          ILogSessionHome logsessionhome = (ILogSessionHome) lookup("java:comp/env/ejb/LogSession",ILogSessionHome.class);       
          logsession = logsessionhome.create();
        }catch(Exception e){
          throw new EJBException(e);   
        }  
        
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
            ICertificateStoreSessionLocal store = storeHome.create(admin);
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
            ISignSessionLocal sign = signHome.create(admin);
            X509CRL crl = sign.createCRL(certs);

            //FileOutputStream fos = new FileOutputStream("srvtestcrl.der");
            //fos.write(crl.getEncoded());
            //fos.close();
        } catch (Exception e) {
            try{
              logsession.log(admin, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CREATECRL,"");       
            }catch(RemoteException re){
              throw new EJBException(re);                
            } 
            throw new EJBException(e);
        }
        debug("<run()");
    }
}


