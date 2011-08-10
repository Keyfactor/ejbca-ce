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

package org.ejbca.core.ejb.ca.store;

import java.math.BigInteger;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.ejb.EJBException;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateData;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.JndiHelper;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.ca.store.CertReqHistory;

/**
 * Stores and manages CertReqHistory entries in the database.
 * CertReqHistory keeps a snapshot of the user data that was used to issue a specific certificate.
 *
 * @version $Id$
 */
@Stateless(mappedName = JndiHelper.APP_JNDI_PREFIX + "CertReqHistorySessionRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CertReqHistorySessionBean implements CertReqHistorySessionRemote, CertReqHistorySessionLocal {

    private final static Logger log = Logger.getLogger(CertReqHistorySessionBean.class);
    /** Internal localization of logs and errors */
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
    
    @PersistenceContext(unitName="ejbca")
    private EntityManager entityManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void addCertReqHistoryData(AuthenticationToken admin, Certificate cert, EndEntityInformation useradmindata){
    	final String issuerDN = CertTools.getIssuerDN(cert);
    	final String username = useradmindata.getUsername();
    	if (log.isTraceEnabled()) {
        	log.trace(">addCertReqHistoryData(" + CertTools.getSerialNumberAsString(cert) + ", " + issuerDN + ", " + username + ")");
    	}
        try {
        	entityManager.persist(new CertReqHistoryData(cert, issuerDN, useradmindata));
        	final String msg = intres.getLocalizedMessage("store.storehistory", username);
        	log.info(msg);
        } catch (Exception e) {
        	final String msg = intres.getLocalizedMessage("store.errorstorehistory", useradmindata.getUsername());
        	log.error(msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<addCertReqHistoryData()");
        }
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public void removeCertReqHistoryData(AuthenticationToken admin, String certFingerprint){
    	if (log.isTraceEnabled()) {
        	log.trace(">removeCertReqHistData(" + certFingerprint + ")");
    	}
        try {          
        	String msg = intres.getLocalizedMessage("store.removehistory", certFingerprint);
        	log.info(msg);
            CertReqHistoryData crh = CertReqHistoryData.findById(entityManager, certFingerprint);
            if (crh == null) {
            	if (log.isDebugEnabled()) {
            		log.debug("Trying to remove CertReqHistory that does not exist: "+certFingerprint);                		
            	}
            } else {
            	entityManager.remove(crh);
            }
        } catch (Exception e) {
        	String msg = intres.getLocalizedMessage("store.errorremovehistory", certFingerprint);
        	log.info(msg);
            throw new EJBException(e);
        }
    	if (log.isTraceEnabled()) {
    		log.trace("<removeCertReqHistData()");
    	}
    }
    
    // getCertReqHistory() might perform database updates, so we always need to run this in a transaction
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public CertReqHistory retrieveCertReqHistory(AuthenticationToken admin, BigInteger certificateSN, String issuerDN){
    	CertReqHistory retval = null;
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByIssuerDNSerialNumber(entityManager, issuerDN, certificateSN.toString());
    	if(result.iterator().hasNext()) {
    		retval = result.iterator().next().getCertReqHistory();
    	}
    	return retval;
    }

    // getCertReqHistory() might perform database updates, so we always need to run this in a transaction
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @Override
    public List<CertReqHistory> retrieveCertReqHistory(AuthenticationToken admin, String username){
    	ArrayList<CertReqHistory> retval = new ArrayList<CertReqHistory>();
    	Collection<CertReqHistoryData> result = CertReqHistoryData.findByUsername(entityManager, username);
    	Iterator<CertReqHistoryData> iter = result.iterator();
    	while(iter.hasNext()) {
    		retval.add(iter.next().getCertReqHistory());
    	}
    	return retval;
    }
    
    @Override
    public CertificateInfo findFirstCertificateInfo(final String issuerDN, final BigInteger serno) {
    	return CertificateData.findFirstCertificateInfo(entityManager, CertTools.stringToBCDNString(issuerDN), serno.toString());
    }

}
