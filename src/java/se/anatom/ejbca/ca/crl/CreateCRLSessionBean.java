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

package se.anatom.ejbca.ca.crl;

import java.math.BigInteger;
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
import se.anatom.ejbca.ca.caadmin.X509CAInfo;
import se.anatom.ejbca.ca.sign.ISignSessionLocal;
import se.anatom.ejbca.ca.sign.ISignSessionLocalHome;
import se.anatom.ejbca.ca.store.CRLInfo;
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
 * @version $Id: CreateCRLSessionBean.java,v 1.21 2004-06-15 16:42:29 sbailliez Exp $
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


     public static long  CRLOVERLAPTIME = 0;


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
          ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) lookup(ILogSessionLocalHome.COMP_NAME,ILogSessionLocalHome.class);       
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
	 * @param issuerdn ofof the ca
	 *
	 * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
	 */
    public void run(Admin admin, String issuerdn)  {
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


    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their
     * CRLs. This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     *
     * @return the number of crls created.
     * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
     */
    public int createCRLs(Admin admin)  {
    	int createdcrls = 0;
    	try {
    		Date currenttime = new Date();
    		ICAAdminSessionLocal caadmin = caadminHome.create();
    		ICertificateStoreSessionLocal store = storeHome.create();

    		Iterator iter = caadmin.getAvailableCAs(admin).iterator();
    		while(iter.hasNext()){
    			int caid = ((Integer) iter.next()).intValue();
    			try{
    			   CAInfo cainfo = caadmin.getCAInfo(admin, caid);
    			   if(cainfo instanceof X509CAInfo){
    			      CRLInfo crlinfo = store.getLastCRLInfo(admin,cainfo.getSubjectDN());
    			      if((currenttime.getTime() + CRLOVERLAPTIME) >= crlinfo.getExpireDate().getTime()){
    			      	 this.run(admin, cainfo.getSubjectDN());

    			      	 createdcrls++;
    			      }
    			   }
    		    }catch(Exception e){
    		    	logsession.log(admin, caid, LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CREATECRL,e.getMessage());
    		    	throw new EJBException(e);
    		    }
    		}
    	} catch (Exception e) {
    		logsession.log(admin, admin.getCAId(), LogEntry.MODULE_CA, new java.util.Date(),null, null, LogEntry.EVENT_ERROR_CREATECRL,e.getMessage());
    		throw new EJBException(e);
    	}

    	return createdcrls;
    }

}


