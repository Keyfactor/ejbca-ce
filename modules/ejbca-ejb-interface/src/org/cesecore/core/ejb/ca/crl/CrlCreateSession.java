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
package org.cesecore.core.ejb.ca.crl;

import java.security.cert.Certificate;
import java.util.Collection;

import org.ejbca.core.model.ca.caadmin.CA;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.catoken.CATokenOfflineException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.log.Admin;

/**
 * Interface for CrlStoreSession, a session bean for performing business
 * operations on CRLs, which mostly entail running them.
 * 
 * @version $Id$
 */
public interface CrlCreateSession {

    /**
     * Requests for a CRL to be created with the passed (revoked) certificates. 
     * Generates the CRL and stores it in the database.
     *
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param certs collection of RevokedCertInfo object.
     * @param basecrlnumber the CRL number of the Base CRL to generate a deltaCRL, -1 to generate a full CRL
     * @return The newly created CRL in DER encoded byte form or null, use CertTools.getCRLfromByteArray to convert to X509CRL.
     * @throws CATokenOfflineException 
     */
    public byte[] createCRL(Admin admin, CA ca, Collection<RevokedCertInfo> certs, int basecrlnumber) throws CATokenOfflineException;

    /**
     * Method that checks if there are any CRLs needed to be updated and then
     * creates their CRLs. No overlap is used. This method can be called by a
     * scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @return the number of crls created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createCRLs(Admin admin);
    
    /**
     * Method that checks if there are any CRLs needed to be updated and then
     * creates their CRLs. A CRL is created: 1. if the current CRL expires
     * within the crloverlaptime (milliseconds) 2. if a crl issue interval is
     * defined (>0) a CRL is issued when this interval has passed, even if the
     * current CRL is still valid
     * 
     * This method can be called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in
     *            which case ALL CAs will be checked
     * @param addtocrloverlaptime
     *            given in milliseconds and added to the CRL overlap time, if
     *            set to how often this method is run (poll time), it can be
     *            used to issue a new CRL if the current one expires within the
     *            CRL overlap time (configured in CA) and the poll time. The
     *            used CRL overlap time will be (crloverlaptime +
     *            addtocrloverlaptime)
     * @return the number of CRLs created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createCRLs(Admin admin, Collection<Integer> caids, long addtocrloverlaptime);
    
    /** Generates the CRL and potentially deltaCRL and stores it in the database. */
    public void createCRLs(Admin admin, CA ca, CAInfo cainfo) throws CATokenOfflineException;
    
    /**
     * Method that checks if there are any delta CRLs needed to be updated and
     * then creates their delta CRLs. No overlap is used. This method can be
     * called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @return the number of delta CRLs created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createDeltaCRLs(Admin admin);

    /**
     * Method that checks if there are any delta CRLs needed to be updated and
     * then creates them. This method can be called by a scheduler or a service.
     * 
     * @param admin administrator performing the task
     * @param caids list of CA ids (Integer) that will be checked, or null in
     *            which case ALL CAs will be checked
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     * @return the number of delta CRLs created.
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public int createDeltaCRLs(Admin admin, Collection<Integer> caids, long crloverlaptime);
    
    /**
     * Method that checks if the CRL is needed to be updated for the CA and
     * creates the CRL, if necessary. A CRL is created: 1. if the current CRL
     * expires within the crloverlaptime (milliseconds) 2. if a CRL issue
     * interval is defined (>0) a CRL is issued when this interval has passed,
     * even if the current CRL is still valid
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param addtocrloverlaptime
     *            given in milliseconds and added to the CRL overlap time, if
     *            set to how often this method is run (poll time), it can be
     *            used to issue a new CRL if the current one expires within the
     *            CRL overlap time (configured in CA) and the poll time. The
     *            used CRL overlap time will be (crloverlaptime +
     *            addtocrloverlaptime)
     * @return true if a CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public boolean runNewTransactionConditioned(Admin admin, CA ca, long addtocrloverlaptime) throws CATokenOfflineException;

    /**
     * Method that checks if the delta CRL needs to be updated and then creates
     * it.
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param crloverlaptime
     *            A new delta CRL is created if the current one expires within
     *            the crloverlaptime given in milliseconds
     * @return true if a Delta CRL was created
     * @throws javax.ejb.EJBException if communication or system error occurs
     */
    public boolean runDeltaCRLnewTransactionConditioned(Admin admin, CA ca, long crloverlaptime) throws CATokenOfflineException;

    /**
     * (Re-)Publish the last CRLs for a CA.
     *
     * @param admin            Information about the administrator performing the event.
     * @param caCert           The certificate for the CA to publish CRLs for
     * @param usedpublishers   a collection if publisher id's (Integer) indicating which publisher that should be used.
     * @param caDataDN         DN from CA data. If a the CA certificate does not have a DN object to be used by the publisher this DN could be searched for the object.
     * @param doPublishDeltaCRL should delta CRLs be published?
     */
    public void publishCRL(Admin admin, Certificate caCert, Collection<Integer> usedpublishers, String caDataDN, boolean doPublishDeltaCRL);
    
    /**
     * Generates a new CRL by looking in the database for revoked certificates
     * and generating a CRL. This method also "archives" certificates when after
     * they are no longer needed in the CRL.
     * Generates the CRL and stores it in the database.
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @return fingerprint (primary key) of the generated CRL or null if
     *            generation failed
     * @throws javax.ejb.EJBException if a communications- or system error occurs
     */
    public String run(Admin admin, CA ca) throws CATokenOfflineException;

    /**
     * Generates a new Delta CRL by looking in the database for revoked
     * certificates since the last complete CRL issued and generating a CRL with
     * the difference. If either of baseCrlNumber or baseCrlCreateTime is -1
     * this method will try to query the database for the last complete CRL.
     * Generates the CRL and stores it in the database.
     * 
     * @param admin administrator performing the task
     * @param ca the CA this operation regards
     * @param baseCrlNumber
     *            base crl number to be put in the delta CRL, this is the CRL
     *            number of the previous complete CRL. If value is -1 the value
     *            is fetched by querying the database looking for the last
     *            complete CRL.
     * @param baseCrlCreateTime
     *            the time the base CRL was issued. If value is -1 the value is
     *            fetched by querying the database looking for the last complete
     *            CRL.
     * @return the bytes of the Delta CRL generated or null of no delta CRL was
     *         generated.
     * @throws javax.ejb.EJBException if a communications- or system error occurs
     */
    public byte[] runDeltaCRL(Admin admin, CA ca, int baseCrlNumber, long baseCrlCreateTime) throws CATokenOfflineException;
    
}
