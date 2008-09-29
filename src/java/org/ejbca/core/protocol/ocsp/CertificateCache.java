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

package org.ejbca.core.protocol.ocsp;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.log4j.Logger;
import org.bouncycastle.ocsp.CertificateID;
import org.bouncycastle.ocsp.OCSPException;
import org.bouncycastle.util.encoders.Hex;
import org.ejbca.core.ejb.ca.store.CertificateDataBean;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.log.Admin;
import org.ejbca.util.CertTools;


/**
 * Class managing a cache of Certificates. This class should be optimized for quick lookups of CA certificates that the 
 * OCSP responder needs to fetch.
 * 
 * @version $Id$
 * 
 */
public class CertificateCache {
	
    /** Log4j instance for Base */
    private static final Logger log = Logger.getLogger(CertificateCache.class);

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    /** Registry of certificates. HashMap is not synchronized, so when updating the HashMap, no read operations should be allowed 
     * The key in this HashMap is the fingerprint of the certificate. */
    private HashMap certCache = null;
    /** Mapping from subjectDN to key in the certs HashMap. */
    private HashMap certsFromSubjectDN = null;
    /** Mapping from CertificateID to key in the certs HashMap. */
    private HashMap certsFromSHA1CertId = null;
    
	/** The interval on which new OCSP signing certs are loaded in seconds. */
	private int m_valid_time;

	/** A semaphore used to stop all processing of HashMaps when we are rebuilding the maps, so we will not get any strange effects
	 * because HashMap is not synchronized
	 */
	private boolean rebuildingMaps = false;
	
	/** A collection that can be used to JUnit test this class. Set responder type to OCSPUtil.RESPONDER_TYPE_TEST
	 * and give a Collection of CA certificate in the initialization properties.
	 */
	private Collection testcerts = null;
	
	/** Cache time counter, set and used by loadCertificates */
	private long m_certValidTo = 0;
	
	/** Admin for calling session beans in EJBCA */
	Admin admin = new Admin(Admin.TYPE_INTERNALUSER);

    /**  
     * @param prop Properties giving initialization parameters. Required parameters are ocspSigningCertsValidTime and ocspResponderType.
     * prop can be set to null to use default values 0 and OCSPUtil.RESPONDER_TYPE_INTERNAL. 
     */
	public CertificateCache(Properties prop) {
		// Default values
		m_valid_time = 0;
		if (prop != null) {
			Object o = prop.get("ocspSigningCertsValidTime");
			if (o != null) {
				Integer i = (Integer)o;
				m_valid_time = i.intValue();    		
			}

			// Pass a collection of CAcerts for testing, if they exist in the properties
			o = prop.get("ocspTestCACerts");
			if (o == null) {
				testcerts = new ArrayList(); // an empty collection
			} else {
				testcerts = (Collection)o;
			}
		}
		loadCertificates();
	}
    
    /** Returns a certificate from the cache.
     * 
     * @param subjectDN the subjectDN of the certificate requested.
     * @return Certificate or null if the certificate does not exist in the cache.
     */
    public X509Certificate findLatestBySubjectDN(String subjectDN) {
        if (null == subjectDN) {
            throw new IllegalArgumentException();
        }
        loadCertificates(); // refresh cache?
        
        // Make sure we don't try to read the HashMaps while they are beeing rebuilt
        while (rebuildingMaps) {
        	try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				log.info(e);
			}
        }
        
        // Do the actual lookup
    	X509Certificate ret = null;
        String key = (String)certsFromSubjectDN.get(CertTools.stringToBCDNString(subjectDN));
        if (key != null) {
        	ret = (X509Certificate)certCache.get(key);
        	if (log.isDebugEnabled()) {
        		log.debug("Found certificate from subjectDN in cache. SubjectDN='"+CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret));
        	}
        }
        return ret;
    }

    /** Finds a certificate in a collection based on the OCSP issuerNameHash and issuerKeyHash
     * 
     * @param certId CertificateId from the OCSP request
     * @param certs the collection of CA certificate to search through
     * @return X509Certificate A CA certificate or null of not found in the collection
     * @throws OCSPException
     */
    public X509Certificate findByHash(CertificateID certId) throws OCSPException {
        if (null == certId) {
            throw new IllegalArgumentException();
        }
        loadCertificates(); // refresh cache?

        // Make sure we don't try to read the HashMaps while they are beeing rebuilt
        while (rebuildingMaps) {
        	try {
				Thread.sleep(50);
			} catch (InterruptedException e) {
				log.info(e);
			}
        }
        // See if we have it in one of the certificate caches
        String key = new String(Hex.encode(certId.getIssuerNameHash()))+new String(Hex.encode(certId.getIssuerKeyHash()));
        String fp = (String)certsFromSHA1CertId.get(key);
        if (fp != null) {
        	X509Certificate ret = (X509Certificate)certCache.get(fp);
        	if (log.isDebugEnabled()) {
        		log.debug("Found certificate from CertificateID in cache. SubjectDN='"+CertTools.getSubjectDN(ret)+"', serno="+CertTools.getSerialNumberAsString(ret));
        	}
        	return ret;
        }
        
        // If we did not find it in the cache, lets look for it the hard way
        Set certs = certCache.entrySet();
        if (null == certs || certs.isEmpty()) {
    		String iMsg = intres.getLocalizedMessage("ocsp.certcollectionempty");
            log.info(iMsg);
            return null;
        }
        Iterator iter = certs.iterator();
        while (iter.hasNext()) {
        	Map.Entry entry = (Map.Entry)iter.next();
            Certificate cert = (Certificate) entry.getValue();
            // OCSP only supports X509 certificates
        	if (cert instanceof X509Certificate) {
                X509Certificate cacert = (X509Certificate) cert;
                try {
                    CertificateID issuerId = new CertificateID(certId.getHashAlgOID(), cacert, CertTools.getSerialNumber(cacert));
                    if (log.isDebugEnabled()) {
                        log.debug("Comparing the following certificate hashes:\n"
                                + " Hash algorithm : '" + certId.getHashAlgOID() + "'\n"
                                + " CA certificate\n"
                                + "      CA SubjectDN: '" + CertTools.getSubjectDN(cacert) + "'\n"
                                + "      SerialNumber: '" + CertTools.getSerialNumberAsString(cacert) + "'\n"
                                + " CA certificate hashes\n"
                                + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
                                + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n"
                                + " OCSP certificate hashes\n"
                                + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
                                + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");
                    }
                    if ((issuerId.toASN1Object().getIssuerNameHash().equals(certId.toASN1Object().getIssuerNameHash()))
                            && (issuerId.toASN1Object().getIssuerKeyHash().equals(certId.toASN1Object().getIssuerKeyHash()))) {
                        if (log.isDebugEnabled()) {
                            log.debug("Found matching CA-cert with:\n"
                                    + "      Name hash : '" + new String(Hex.encode(issuerId.getIssuerNameHash())) + "'\n"
                                    + "      Key hash  : '" + new String(Hex.encode(issuerId.getIssuerKeyHash())) + "'\n");                    
                        }
                        return cacert;
                    }
                } catch (OCSPException e) {
            		String errMsg = intres.getLocalizedMessage("ocsp.errorcomparehash", cacert.getIssuerDN());
                    log.error(errMsg, e);
                }        		
        	} else {
        		if (log.isDebugEnabled()) {
            		log.debug("Certificate not an X509 Certificate. Issuer '"+CertTools.getSubjectDN(cert)+"'");        			
        		}
        	}
        }
        if (log.isDebugEnabled()) {
            log.debug("Did not find matching CA-cert for:\n"
                    + "      Name hash : '" + new String(Hex.encode(certId.getIssuerNameHash())) + "'\n"
                    + "      Key hash  : '" + new String(Hex.encode(certId.getIssuerKeyHash())) + "'\n");            
        }
        return null;
    }
    
    public void forceReload() {
    	m_certValidTo = 0;
    	loadCertificates();
    }
    
    /* private helper methods */
    
    private void loadCertificates() {
    	/** Loads CA certificates but holds a cache so it's reloaded only every five minutes (configurable).
    	 */
    	// Check if we have a cached collection that is not too old
    	if (certCache != null && m_certValidTo > new Date().getTime()) {
    		// The other HashMaps are always created as well, if this one is created
    		return;
    	}
    	
    	// We have to set the semaphore so noone accesses the HashMaps while we are rebuilding them
    	try {
        	rebuildingMaps = true;
        	Collection certs = findCertificatesByType(admin, CertificateDataBean.CERTTYPE_SUBCA + CertificateDataBean.CERTTYPE_ROOTCA, null);
        	if (log.isDebugEnabled()) {
        		log.debug("Loaded "+certs == null ? "0":certs.size()+" ca certificates");        	
        	}
        	// Set up certsFromSubjectDN, certsFromSHA1CertId and certCache
        	certCache = new HashMap();
        	certsFromSubjectDN = new HashMap();
        	certsFromSHA1CertId = new HashMap();
        	Iterator i = certs.iterator();
        	while (i.hasNext()) {
        		Certificate cert = (Certificate)i.next();
        		if (cert instanceof X509Certificate) {
            		String fp = CertTools.getFingerprintAsString(cert);
            		certCache.put(fp, cert);
            		String subjectDN = CertTools.getSubjectDN(cert);
            		// Check if we already have a certificate from this issuer in the HashMap. 
            		// We only want to store the latest cert from each issuer in this map
            		String lfp = (String)certsFromSubjectDN.get(subjectDN);
            		if (lfp != null) {
                    	X509Certificate pcert = (X509Certificate)certCache.get(lfp);
                    	if (CertTools.getNotBefore(cert).after(CertTools.getNotBefore(pcert))) {
                    		certsFromSubjectDN.put(subjectDN, fp);                    		
                    	}
            		} else {
                		certsFromSubjectDN.put(subjectDN, fp);                    		
            		}
            		// We only need issuerNameHash and issuerKeyHash from certId
            		try {
                		CertificateID certId = new CertificateID(CertificateID.HASH_SHA1, (X509Certificate)cert, new BigInteger("1"));
                		String key = new String(Hex.encode(certId.getIssuerNameHash()))+new String(Hex.encode(certId.getIssuerKeyHash()));
                		certsFromSHA1CertId.put(key, fp);
            		} catch (OCSPException e) {
            			log.info(e);
            		}
        		} else {
        			log.debug("Not adding CA certificate of type: "+cert.getType());
        		}
        	}    		
    	} finally {
    		// Make absolutely sure we always reset it to false
    		rebuildingMaps = false;
    	}
    		    	
    	// If m_valid_time == 0 we set reload time to Long.MAX_VALUE, which should be forever, so the cache is never refreshed
    	m_certValidTo = m_valid_time>0 ? new Date().getTime()+m_valid_time : Long.MAX_VALUE;

    	if (log.isDebugEnabled()) {
    		StringBuffer certInfo = new StringBuffer();
    		Set keys = certCache.keySet();
    		Iterator iter = keys.iterator();
    		while (iter.hasNext()) {
    			String key = (String)iter.next();
    			Certificate cert = (Certificate)certCache.get(key);
    			certInfo.append(CertTools.getSubjectDN(cert));
    			certInfo.append(',');
    			certInfo.append(CertTools.getSerialNumberAsString(cert));
    			certInfo.append('\n');
    		}
    		log.debug("Found the following CA certificates : \n"
    				+ certInfo.toString());
    	}
    } // loadCertificates
    
    /**
     * 
     * @param adm
     * @param type
     * @param issuerDN
     * @return Collection of Certificate never null
     */
    protected Collection findCertificatesByType(Admin adm, int type, String issuerDN) {
    	// Use classes CertificateCacheStandalone or CertificateCacheInternal for non-test caches
    	return testcerts;
    }

}
