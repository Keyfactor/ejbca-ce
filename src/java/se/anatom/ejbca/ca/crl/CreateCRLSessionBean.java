package se.anatom.ejbca.ca.crl;

import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.cert.X509CRL;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.Vector;

import javax.ejb.CreateException;
import javax.ejb.EJBException;

import se.anatom.ejbca.BaseSessionBean;
import se.anatom.ejbca.IJobRunnerSession;
import se.anatom.ejbca.ca.exception.CADoesntExistsException;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocal;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionLocalHome;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.CertificateData;
import se.anatom.ejbca.ca.store.CertificateDataLocal;
import se.anatom.ejbca.ca.store.CertificateDataLocalHome;
import se.anatom.ejbca.ca.store.CertificateDataPK;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocal;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionLocalHome;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.log.ILogSessionLocal;
import se.anatom.ejbca.log.ILogSessionLocalHome;
import se.anatom.ejbca.log.LogEntry;


/**
 * Generates a new CRL by looking in the database for revoked certificates and
 * generating a CRL.
 *
 * @version $Id: CreateCRLSessionBean.java,v 1.17 2003-11-03 14:00:31 anatom Exp $
 */
public class CreateCRLSessionBean extends BaseSessionBean implements IJobRunnerSession {
    

    /** The local home interface of Certificate store */
    private ICertificateStoreSessionLocalHome storeHome = null;

    /** The local home interface of Certificate entity bean */
    private CertificateDataLocalHome certHome = null;

    /** The local home interface of the signing session */
    private ISignSessionLocalHome signHome = null;

    /** The local home interface of the caadmin session */
    private ICAAdminSessionLocalHome caadminHome = null;    
    
    /** The local interface of the log session bean */
    private ILogSessionLocal logsession;        
    
   
    
    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        debug(">ejbCreate()");
        caadminHome = (ICAAdminSessionLocalHome)lookup("java:comp/env/ejb/CAAdminSessionLocal");
        storeHome = (ICertificateStoreSessionLocalHome)lookup("java:comp/env/ejb/CertificateStoreSessionLocal");
        certHome = (CertificateDataLocalHome)lookup("java:comp/env/ejb/CertificateDataLocal");
        signHome = (ISignSessionLocalHome)lookup("java:comp/env/ejb/SignSessionLocal");
        
        try{
          ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup("java:comp/env/ejb/LogSessionLocal",ILogSessionLocalHome.class);       
          logsession = logsessionhome.create();
        }catch(Exception e){
          throw new EJBException(e);   
        }  
        
        debug("<ejbCreate()");
    }

	/**
	 * Generates a new CRL by looking in the database for revoked certificates and generating a
	 * CRL.
	 *
	 * @param admin administrator performing the task
	 *
	 * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
	 */
    public void run(Admin admin, String issuerdn) throws RemoteException {
        debug(">run()");
        int caid = issuerdn.hashCode();
        try {       
            ICAAdminSessionLocal caadmin = caadminHome.create();
            ICertificateStoreSessionLocal store = storeHome.create();
            
            CAInfo cainfo = caadmin.getCAInfo(admin, caid);
            if (cainfo == null) {
                throw new CADoesntExistsException("CA not found: "+issuerdn);
            }
            int crlperiod = cainfo.getCRLPeriod();
            // Find all revoked certificates
            Collection revcerts = store.listRevokedCertificates(admin, issuerdn);
            debug("Found "+revcerts.size()+" revoked certificates.");

            // Go through them and create a CRL, at the same time archive expired certificates
            Date now = new Date();
            // crlperiod is hours = crlperiod*60*60*1000 milliseconds
            now.setTime(now.getTime() - (crlperiod * 60 * 60 * 1000));
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
            ISignSessionLocal sign = signHome.create();
            X509CRL crl = (X509CRL) sign.createCRL(admin, caid, certs);

            //FileOutputStream fos = new FileOutputStream("srvtestcrl.der");
            //fos.write(crl.getEncoded());
            //fos.close();
        } catch (Exception e) {            
            logsession.log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CREATECRL,e.getMessage());                
            throw new EJBException(e);
        }
        debug("<run()");
    }
}


