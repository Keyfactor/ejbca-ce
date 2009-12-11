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

package org.ejbca.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;

import org.ejbca.core.ejb.BaseSessionBean;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataLocal;
import org.ejbca.core.ejb.ca.store.CertificateDataLocalHome;
import org.ejbca.core.ejb.ca.store.CertificateDataPK;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.caadmin.X509CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CRLInfo;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogConstants;
import org.ejbca.util.CertTools;


/**
 * Generates a new CRL by looking in the database for revoked certificates and
 * generating a CRL.
 *
 * @version $Id$
 * @ejb.bean
 *   description="Session bean handling hard token data, both about hard tokens and hard token issuers."
 *   display-name="CreateCRLSB"
 *   name="CreateCRLSession"
 *   jndi-name="CreateCRLSession"
 *   local-jndi-name="CreateCRLSessionLocal"
 *   view-type="both"
 *   type="Stateless"
 *   transaction-type="Container"
 *
 * @ejb.transaction type="Required"
 *
 * @weblogic.enable-call-by-reference True
 * 
 * Increase transaction timeout for all methods in this class to one hour on JBoss.
 * @jboss.method-attributes pattern="*" transaction-timeout="3600"
 *
 * @ejb.home
 *   extends="javax.ejb.EJBHome"
 *   local-extends="javax.ejb.EJBLocalHome"
 *   local-class="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocalHome"
 *   remote-class="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionHome"
 *
 * @ejb.interface
 *   extends="javax.ejb.EJBObject"
 *   local-extends="javax.ejb.EJBLocalObject"
 *   local-class="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionLocal"
 *   remote-class="org.ejbca.core.ejb.ca.crl.ICreateCRLSessionRemote"
 *   
 * @ejb.ejb-external-ref
 *   description="The log session bean"
 *   view-type="local"
 *   ref-name="ejb/LogSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.log.ILogSessionLocalHome"
 *   business="org.ejbca.core.ejb.log.ILogSessionLocal"
 *   link="LogSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Certificate entity bean used manipulate certificates"
 *   view-type="local"
 *   ref-name="ejb/CertificateDataLocal"
 *   type="Entity"
 *   home="org.ejbca.core.ejb.ca.store.CertificateDataLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.CertificateDataLocal"
 *   link="CertificateData"
 *
 * @ejb.ejb-external-ref
 *   description="The CA Admin Session"
 *   view-type="local"
 *   ref-name="ejb/CAAdminSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal"
 *   link="CAAdminSession"
 *
 * @ejb.ejb-external-ref
 *   description="The Certificate Store session bean"
 *   view-type="local"
 *   ref-name="ejb/CertificateStoreSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal"
 *   link="CertificateStoreSession"
 *
 * @ejb.ejb-external-ref
 *   description="The signing session used to create CRL"
 *   view-type="local"
 *   ref-name="ejb/RSASignSessionLocal"
 *   type="Session"
 *   home="org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome"
 *   business="org.ejbca.core.ejb.ca.sign.ISignSessionLocal"
 *   link="RSASignSession"
 *
 */
public class CreateCRLSessionBean extends BaseSessionBean {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    
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

    private static final long DEFAULTCRLOVERLAPTIME = 0;

    /** Default create for SessionBean without any creation Arguments.
     * @throws CreateException if bean instance can't be created
     */
    public void ejbCreate () throws CreateException {
        caadminHome = (ICAAdminSessionLocalHome)getLocator().getLocalHome(ICAAdminSessionLocalHome.COMP_NAME);
        storeHome = (ICertificateStoreSessionLocalHome)getLocator().getLocalHome(ICertificateStoreSessionLocalHome.COMP_NAME);
        certHome = (CertificateDataLocalHome)getLocator().getLocalHome(CertificateDataLocalHome.COMP_NAME);
        signHome = (ISignSessionLocalHome)getLocator().getLocalHome(ISignSessionLocalHome.COMP_NAME);
        ILogSessionLocalHome logsessionhome = (ILogSessionLocalHome) getLocator().getLocalHome(ILogSessionLocalHome.COMP_NAME);
        logsession = logsessionhome.create();
    }

	/** Same as generating a new CRL but this is in a new separate transaction.
	 *
     * @ejb.interface-method
     * @ejb.transaction type="RequiresNew"
	 */
    public void runNewTransaction(Admin admin, String issuerdn) throws CATokenOfflineException {
    	run(admin,issuerdn);
    }
	/** Same as generating a new delta CRL but this is in a new separate transaction.
	 * 
     * @ejb.interface-method
     * @ejb.transaction type="RequiresNew"
     */
    public byte[] runDeltaCRLnewTransaction(Admin admin, String issuerdn)  {
    	return runDeltaCRL(admin, issuerdn, -1, -1);
    }

	/**
	 * Generates a new CRL by looking in the database for revoked certificates and generating a
	 * CRL. This method also "archives" certificates when after they are no longer needed in the CRL. 
	 *
	 * @param admin administrator performing the task
	 * @param issuerdn of the ca (normalized for EJBCA)
	 * @return fingerprint (primarey key) of the generated CRL or null if generation failed
	 * 
	 * @throws EJBException if a communications- or system error occurs
     * @ejb.interface-method
	 */
    public String run(Admin admin, String issuerdn) throws CATokenOfflineException {
        trace(">run()");
        int caid = issuerdn.hashCode();
        String ret = null;
        try {
            ICAAdminSessionLocal caadmin = caadminHome.create();
            ICertificateStoreSessionLocal store = storeHome.create();

            CAInfo cainfo = caadmin.getCAInfo(admin, caid);
            if (cainfo == null) {
                throw new CADoesntExistsException("CA not found: "+issuerdn);
            }
            final String caCertSubjectDN; // DN from the CA issuing the CRL to be used when searching for the CRL in the database.
            {
            	final Collection certs = cainfo.getCertificateChain();
            	final Certificate cacert = !certs.isEmpty() ? (Certificate)certs.iterator().next(): null;
            	caCertSubjectDN = cacert!=null ? CertTools.getSubjectDN(cacert) : null;
            }
            // We can not create a CRL for a CA that is waiting for certificate response
            if ( caCertSubjectDN!=null && cainfo.getStatus()==SecConst.CA_ACTIVE )  {
            	long crlperiod = cainfo.getCRLPeriod();
            	// Find all revoked certificates for a complete CRL
            	Collection revcerts = store.listRevokedCertInfo(admin, caCertSubjectDN, -1);
            	debug("Found "+revcerts.size()+" revoked certificates.");

            	// Go through them and create a CRL, at the same time archive expired certificates
            	Date now = new Date();
            	Date check = new Date(now.getTime() - crlperiod);
            	Iterator iter = revcerts.iterator();
            	while (iter.hasNext()) {
            		RevokedCertInfo data = (RevokedCertInfo)iter.next();
            		// We want to include certificates that was revoked after the last CRL was issued, but before this one
            		// so the revoked certs are included in ONE CRL at least. See RFC5280 section 3.3.
            		if ( data.getExpireDate().before(check) ) {
            			// Certificate has expired, set status to archived in the database 
            			setArchivedStatus(data.getCertificateFingerprint());
            		} else {
                		Date revDate = data.getRevocationDate();
            			if (revDate == null) {
            				data.setRevocationDate(now);
            				CertificateDataPK pk = new CertificateDataPK(data.getCertificateFingerprint());
            				CertificateDataLocal certdata = certHome.findByPrimaryKey(pk);
            				// Set revocation date in the database
            				certdata.setRevocationDate(now);
            			}
            		}
            	}
            	ISignSessionLocal sign = signHome.create();
            	// a full CRL
            	byte[] crlBytes = sign.createCRL(admin, caid, revcerts, -1);
            	if (crlBytes != null) {
                	ret = CertTools.getFingerprintAsString(crlBytes);            		
            	}
            	// This is logged in the database by SignSession 
            	String msg = intres.getLocalizedMessage("createcrl.createdcrl", cainfo.getName(), cainfo.getSubjectDN());            	
            	log.info(msg);
            	// This debug logging is very very heavy if you have large CRLs. Please don't use it :-)
//          	if (log.isDebugEnabled()) {
//          	X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
//          	debug("Created CRL with expire date: "+crl.getNextUpdate());
//          	FileOutputStream fos = new FileOutputStream("c:\\java\\srvtestcrl.der");
//          	fos.write(crl.getEncoded());
//          	fos.close();
//          	}
            } else {
            	String msg = intres.getLocalizedMessage("createcrl.errornotactive", cainfo.getName(), new Integer(caid), cainfo.getStatus());            	    			    	   
            	log.info(msg);            	
            }
        } catch (CATokenOfflineException e) {
            throw e;            
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("createcrl.errorcreate", new Integer(caid));            	
            log.error(msg, e);
            logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg, e);
            throw new EJBException(e);
        }
        trace("<run()");
        return ret;
    } // run

	/**
	 * This method sets the "archived" certificates status. Normally this is done by the CRL-creation process.
	 * This is also used from the createLotsOfCertsPerUser test.
	 *
	 * @param certificateFingerprint is the fingerprint of the certifiate
	 * @throws FinderException is thrown when no such certificate exists
	 *
     * @ejb.interface-method
	 */
    public void setArchivedStatus(String certificateFingerprint) throws FinderException {
		CertificateDataPK pk = new CertificateDataPK(certificateFingerprint);
		CertificateDataLocal certdata = certHome.findByPrimaryKey(pk);
		certdata.setStatus(SecConst.CERT_ARCHIVED);
    }
    
    /**
     * Generates a new Delta CRL by looking in the database for revoked certificates since the last complete CRL issued and generating a
     * CRL with the difference. If either of baseCrlNumber or baseCrlCreateTime is -1 this method will try to query the database for the last complete CRL.
     *
     * @param admin administrator performing the task
     * @param issuerdn of the ca
     * @param baseCrlNumber base crl number to be put in the delta CRL, this is the CRL number of the previous complete CRL. If value is -1 the value is fetched by querying the database looking for the last complete CRL.
     * @param baseCrlCreateTime the time the base CRL was issued. If value is -1 the value is fetched by querying the database looking for the last complete CRL. 
     * @return the bytes of the Delta CRL generated or null of no delta CRL was generated.
     * 
     * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
     * @ejb.interface-method
     */
    public byte[] runDeltaCRL(Admin admin, String issuerdn, int baseCrlNumber, long baseCrlCreateTime)  {
    	if (log.isTraceEnabled()) {
        	log.trace(">runDeltaCRL: "+issuerdn);
    	}
    	byte[] crlBytes = null;
    	final int caid = issuerdn.hashCode();
    	try {
    		final ICAAdminSessionLocal caadmin = caadminHome.create();
    		final ICertificateStoreSessionLocal store = storeHome.create();
    		final CAInfo cainfo = caadmin.getCAInfo(admin, caid);
    		if (cainfo == null) {
    			throw new CADoesntExistsException("CA not found: "+issuerdn);
    		}
    		final String caCertSubjectDN; {
    		    final Collection certs = cainfo.getCertificateChain();
    		    final Certificate cacert = !certs.isEmpty() ? (Certificate)certs.iterator().next(): null;
                caCertSubjectDN = cacert!=null ? CertTools.getSubjectDN(cacert) : null;
            }
    		if (caCertSubjectDN!=null && cainfo instanceof X509CAInfo) { // Only create CRLs for X509 CAs
    			if ( (baseCrlNumber == -1) && (baseCrlCreateTime == -1) ) {
        			CRLInfo basecrlinfo = store.getLastCRLInfo(admin, caCertSubjectDN, false);
        			baseCrlCreateTime = basecrlinfo.getCreateDate().getTime();
        			baseCrlNumber = basecrlinfo.getLastCRLNumber();    				
    			}
    			// Find all revoked certificates
    			Collection revcertinfos = store.listRevokedCertInfo(admin, caCertSubjectDN, baseCrlCreateTime);
    			debug("Found "+revcertinfos.size()+" revoked certificates.");
    			// Go through them and create a CRL, at the same time archive expired certificates
    			ArrayList certs = new ArrayList();
    			Iterator iter = revcertinfos.iterator();
    			while (iter.hasNext()) {
    				RevokedCertInfo ci = (RevokedCertInfo)iter.next();
    				if (ci.getRevocationDate() == null) {
    					ci.setRevocationDate(new Date());
    				}
    				certs.add(ci);
    			}
    			ISignSessionLocal sign = signHome.create();
    			// create a delta CRL
    			crlBytes = sign.createCRL(admin, caid, certs, baseCrlNumber);
    			X509CRL crl = CertTools.getCRLfromByteArray(crlBytes);
    			debug("Created delta CRL with expire date: "+crl.getNextUpdate());
    		}
    	} catch (Exception e) {
    		logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,e.getMessage());
    		throw new EJBException(e);
    	}
    	if (log.isTraceEnabled()) {
        	log.trace("<runDeltaCRL: "+issuerdn);
    	}
		return crlBytes;
    } // runDeltaCRL
        
        
    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their
     * CRLs. No overlap is used. This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     *
     * @return the number of crls created.
     * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
     * @ejb.interface-method 
     */
    public int createCRLs(Admin admin)  {
        return createCRLs(admin, null, DEFAULTCRLOVERLAPTIME);
    }
    /**
     * Method that checks if there are any delta CRLs needed to be updated and then creates their
     * delta CRLs. No overlap is used. This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     *
     * @return the number of delta crls created.
     * @throws EJBException if communication or system error happens
     * @ejb.interface-method 
     */
    public int createDeltaCRLs(Admin admin)  {
    	return this.createDeltaCRLs(admin, null, DEFAULTCRLOVERLAPTIME);
    }
    
    /**
     * Method that checks if there are any CRLs needed to be updated and then creates their
     * CRLs. A CRL is created:
     * 1. if the current CRL expires within the crloverlaptime (milliseconds)
     * 2. if a crl issue interval is defined (>0) a CRL is issued when this interval has passed, even if the current CRL is still valid
     *  
     * This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked
     * @param addtocrloverlaptime given in milliseconds and added to the CRL overlap time, if set to how often this method is run (poll time), it can be used to issue a new CRL if the current one expires within
     * the CRL overlap time (configured in CA) and the poll time. The used CRL overlap time will be (crloverlaptime + addtocrloverlaptime) 
     *
     * @return the number of crls created.
     * @throws EJBException om ett kommunikations eller systemfel intr?ffar.
     * @ejb.interface-method 
     */
    public int createCRLs(Admin admin, Collection caids, long addtocrloverlaptime)  {
    	int createdcrls = 0;
    	try {
    		Date currenttime = new Date();
    		ICAAdminSessionLocal caadmin = caadminHome.create();
    		ICertificateStoreSessionLocal store = storeHome.create();

    		Iterator iter = null;
    		if (caids != null) {
    			iter = caids.iterator();
    		} 
    		if ( (iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS))) ) {
        		iter = caadmin.getAvailableCAs().iterator();
    		}
    		while(iter.hasNext()){
    			int caid = ((Integer) iter.next()).intValue();
    			log.debug("createCRLs for caid: "+caid);
    			try {
    			   CAInfo cainfo = caadmin.getCAInfo(admin, caid);
    			   if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
    				   log.debug("Not trying to generate CRL for external CA "+cainfo.getName());
    			   } else if (cainfo.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
    				   log.debug("Not trying to generate CRL for CA "+cainfo.getName() +" awaiting certificate response.");
    			   } else {
        			   if (cainfo instanceof X509CAInfo) {
        				   Collection certs = cainfo.getCertificateChain();
        				   final Certificate cacert;
        				   if (!certs.isEmpty()) {
        					   cacert = (Certificate)certs.iterator().next();   
        				   } else {
        				       cacert = null;
        				   }
        				   // Don't create CRLs if the CA has expired
        				   if ( (cacert != null) && (CertTools.getNotAfter(cacert).after(new Date())) ) {
            			       if (cainfo.getStatus() == SecConst.CA_OFFLINE )  {
            			    	   String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), new Integer(caid));            	    			    	   
            			    	   log.info(msg);
            			    	   logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_INFO_CREATECRL, msg);
            			       } else {
            			           try {
            			        	   if (log.isDebugEnabled()) {
            			        		   log.debug("Checking to see if CA '"+cainfo.getName()+"' ("+cainfo.getCAId()+") needs CRL generation.");
            			        	   }
            			               final String certSubjectDN = CertTools.getSubjectDN(cacert);
            			               CRLInfo crlinfo = store.getLastCRLInfo(admin,certSubjectDN,false);
            			               if (log.isDebugEnabled()) {
                			               if (crlinfo == null) {
                			            	   log.debug("Crlinfo was null");
                			               } else {
                			            	   log.debug("Read crlinfo for CA: "+cainfo.getName()+", lastNumber="+crlinfo.getLastCRLNumber()+", expireDate="+crlinfo.getExpireDate());
                			               }    			            	   
            			               }
                                       long crlissueinterval = cainfo.getCRLIssueInterval();
                                       if (log.isDebugEnabled()) {
                                           log.debug("crlissueinterval="+crlissueinterval);
                                           log.debug("crloverlaptime="+cainfo.getCRLOverlapTime());                            	   
                                       }
                                       long overlap = cainfo.getCRLOverlapTime() + addtocrloverlaptime; // Overlaptime is in minutes, default if crlissueinterval == 0
                                       long nextUpdate = 0; // if crlinfo == 0, we will issue a crl now
                                       if (crlinfo != null) {
                                           // CRL issueinterval in hours. If this is 0, we should only issue a CRL when
                                           // the old one is about to expire, i.e. when currenttime + overlaptime > expiredate
                                           // if isseuinterval is > 0 we will issue a new CRL when currenttime > createtime + issueinterval
                                           nextUpdate = crlinfo.getExpireDate().getTime(); // Default if crlissueinterval == 0
                                           if (crlissueinterval > 0) {
                                               long u = crlinfo.getCreateDate().getTime() + crlissueinterval;
                                               // If this period for some reason (we missed to issue some?) is larger than when the CRL expires,
                                               // we need to issue one when the CRL expires
                                               if ((u + overlap) < nextUpdate) {
                                                   nextUpdate = u;
                                                   // When we issue CRLs before the real expiration date we don't use overlap
                                                   overlap = 0;
                                               }
                                           }                                   
                                           log.debug("Calculated nextUpdate to "+nextUpdate);
                                       } else {
                    			    	   String msg = intres.getLocalizedMessage("createcrl.crlinfonull", cainfo.getName());            	    			    	   
                                    	   log.info(msg);
                                       }
            			               if ((currenttime.getTime() + overlap) >= nextUpdate) {
            			            	   if (log.isDebugEnabled()) {
                			            	   log.debug("Creating CRL for CA, because:"+currenttime.getTime()+overlap+" >= "+nextUpdate);    			            		   
            			            	   }
            			                   this.runNewTransaction(admin, cainfo.getSubjectDN());
            			                   createdcrls++;
            			               }
            			               
            			           } catch (CATokenOfflineException e) {
                			    	   String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), new Integer(caid));            	    			    	   
                			    	   log.error(msg);
                			    	   logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg);
            			           }
            			       }
        			       } else if (cacert != null) {
        			    	   log.debug("Not creating CRL for expired CA "+cainfo.getName()+". CA subjectDN='"+CertTools.getSubjectDN(cacert)+"', expired: "+CertTools.getNotAfter(cacert));    			    	   
        			       } else {
        			    	   log.debug("Not creating CRL for CA without CA certificate: "+cainfo.getName());    			    	           			    	   
        			       }
        			   }                           				   
    			   }
                } catch(Exception e) {
                	String msg = intres.getLocalizedMessage("createcrl.generalerror", new Integer(caid));            	    			    	   
                	error(msg, e);
                	logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
                	if (e instanceof EJBException) {
                		throw (EJBException)e;
                	}
                	throw new EJBException(e);
    		    }
    		}
    	} catch (Exception e) {
        	String msg = intres.getLocalizedMessage("createcrl.erroravailcas");            	    			    	   
        	error(msg, e);
    		logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
            if (e instanceof EJBException) {
                throw (EJBException)e;
            }
    		throw new EJBException(e);
    	}

    	return createdcrls;
    }

    
    /**
     * Method that checks if there are any delta CRLs needed to be updated and then creates them.
     * This method can be called by a scheduler or a service.
     *
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in which case ALL CAs will be checked
     * @param crloverlaptime A new delta CRL is created if the current one expires within the crloverlaptime given in milliseconds
     *
     * @return the number of delta crls created.
     * @throws EJBException 
     * @ejb.interface-method 
     */
    public int createDeltaCRLs(Admin admin, Collection caids, long crloverlaptime)  {
    	int createddeltacrls = 0;
    	try {
    		Date currenttime = new Date();
    		ICAAdminSessionLocal caadmin = caadminHome.create();
    		ICertificateStoreSessionLocal store = storeHome.create();

    		Iterator iter = null;
    		if (caids != null) {
    			iter = caids.iterator();
    		}
    		if ( (iter == null) || (caids.contains(Integer.valueOf(SecConst.ALLCAS))) ) {
        		iter = caadmin.getAvailableCAs().iterator();
    		}
    		while (iter.hasNext()) {
    			int caid = ((Integer) iter.next()).intValue();
    			log.debug("createDeltaCRLs for caid: "+caid);
    			try{
    				CAInfo cainfo = caadmin.getCAInfo(admin, caid);
    				if (cainfo.getStatus() == SecConst.CA_EXTERNAL) {
    					log.debug("Not trying to generate delta CRL for external CA "+cainfo.getName());
    				} else if (cainfo.getStatus() == SecConst.CA_WAITING_CERTIFICATE_RESPONSE) {
    					log.debug("Not trying to generate delta CRL for CA "+cainfo.getName() +" awaiting certificate response.");
    				} else {
        				if (cainfo instanceof X509CAInfo) {
        					Collection certs = cainfo.getCertificateChain();
        					final Certificate cacert;
        					if (!certs.isEmpty()) {
        						cacert = (Certificate)certs.iterator().next();   
        					} else {
        					    cacert = null;
        					}
        					// Don't create CRLs if the CA has expired
        					if ( (cacert != null) && (CertTools.getNotAfter(cacert).after(new Date())) ) {
            					if(cainfo.getDeltaCRLPeriod() > 0) {
            						if (cainfo.getStatus() == SecConst.CA_OFFLINE) {
            							String msg = intres.getLocalizedMessage("createcrl.caoffline", cainfo.getName(), new Integer(caid));            	    			    	   
            							log.error(msg);
            							logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL, msg);
            						} else {
            							if (log.isDebugEnabled()) {
            								log.debug("Checking to see if CA '"+cainfo.getName()+"' needs Delta CRL generation.");
            							}
            							final String certSubjectDN = CertTools.getSubjectDN(cacert);
            							CRLInfo deltacrlinfo = store.getLastCRLInfo(admin, certSubjectDN, true);
            							if (log.isDebugEnabled()) {
            								if (deltacrlinfo == null) {
            									log.debug("DeltaCrlinfo was null");
            								} else {
            									log.debug("Read deltacrlinfo for CA: "+cainfo.getName()+", lastNumber="+deltacrlinfo.getLastCRLNumber()+", expireDate="+deltacrlinfo.getExpireDate());
            								}    			            	   
            							}
            							if((deltacrlinfo == null) || ((currenttime.getTime() + crloverlaptime) >= deltacrlinfo.getExpireDate().getTime())){
            								this.runDeltaCRLnewTransaction(admin, cainfo.getSubjectDN());
            								createddeltacrls++;
            							}
            						}
            					}
        					} else if (cacert != null) {
        						log.debug("Not creating delta CRL for expired CA "+cainfo.getName()+". CA subjectDN='"+CertTools.getSubjectDN(cacert)+"', expired: "+CertTools.getNotAfter(cacert));    			    	   
        					} else {
        						log.debug("Not creating delta CRL for CA without CA certificate: "+cainfo.getName());    			    	           			    	   
        					}
        				}    					
    			   }
    			}catch(Exception e) {
                	String msg = intres.getLocalizedMessage("createcrl.generalerror", new Integer(caid));            	    			    	   
                	error(msg, e);
                	logsession.log(admin, caid, LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
                	if (e instanceof EJBException) {
                		throw (EJBException)e;
                	}
                	throw new EJBException(e);
    			}
    		}
    	} catch (Exception e) {
        	String msg = intres.getLocalizedMessage("createcrl.erroravailcas");            	    			    	   
        	error(msg, e);
    		logsession.log(admin, admin.getCaId(), LogConstants.MODULE_CA, new java.util.Date(),null, null, LogConstants.EVENT_ERROR_CREATECRL,msg,e);
            if (e instanceof EJBException) {
                throw (EJBException)e;
            }
    		throw new EJBException(e);
    	}

    	return createddeltacrls;
    }


}

