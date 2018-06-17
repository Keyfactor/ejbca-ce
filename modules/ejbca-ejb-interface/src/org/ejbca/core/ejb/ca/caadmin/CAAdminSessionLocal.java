/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.core.ejb.ca.caadmin;

import java.security.cert.CertificateEncodingException;
import java.util.Collection;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.audit.enums.EventType;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.certificates.certificate.CertificateRevokeException;
import org.cesecore.certificates.certificate.CertificateWrapper;
import org.ejbca.core.EjbcaException;

@Local
public interface CAAdminSessionLocal extends CAAdminSession {

	/**
     * A method designed to be called at startup time to speed up the (next)
     * first request to a CA. This method will initialize the CA-cache with all
     * CAs, if they are not already in the cache. Can have a side-effect of
     * upgrading a CA, therefore the Required transaction setting.
     */
    void initializeAndUpgradeCAs();

    /** Method that loads a CA in order to possibly upgrade it, in a separate transaction. 
     * This method is called from initializeAndUpgradeCAs in order to limit the transaction scope of CA upgrades.
     * @param caid The CA to load/upgrade
     * @throws CADoesntExistsException is the CA does not exist
     */
    void initializeAndUpgradeCA(Integer caid) throws CADoesntExistsException;

    /**
     * Used by health-check. Validate that CAs are online and optionally performs
     * a signature test.
     * 
     * @return an error message or an empty String if all are ok.
     */
    String healthCheck();

    /**
     * Regenerates the CMS certificate for a CA.
     */
    void renewAndRevokeCmsCertificate(AuthenticationToken admin, int caid) throws AuthorizationDeniedException, CADoesntExistsException,
            CAOfflineException, CertificateRevokeException;
    
//    /**
//     * Checks if at least one CA references a key validator.
//     * @param keyValidatorId
//     * @return true if there are no references.
//     * 
//     * @throws AuthorizationDeniedException if not authorized.
//     */
//    boolean existsKeyValidatorInCAs(int keyValidatorId) throws AuthorizationDeniedException;
//    
    /** 
     * This method returns a set containing IDs of all authorized key validators. This set will be the sum of the following:
     * 
     * * Unassigned key validators
     * * Key validators assigned to CAs that the administrator has access to.
     * 
     * @return a Set of IDs of authorized key validators. 
     */
    Set<Integer> getAuthorizedKeyValidatorIds(AuthenticationToken admin);
    
    /**
     * Writes a custom audit log into the database.
     *
     * Authorization requirements: <pre>
     * - /administrator
     * - /secureaudit/log_custom_events (must be configured in advanced mode when editing access rules)
     * </pre>
     *
     * @param level the logging level of the event ({@link org.ejbca.core.ejb.audit.enums.EjbcaEventTypes}).
     * @param type a user defined string used as a prefix in the log comment.
     * @param caName the name of the CA related to the event or null for the administrators CA to be used.
     * @param username the name of the related user or null if no related user exists.
     * @param certificate the certificate related to the log event or null if no certificate is related to this log event.
     * @param msg the message data used in the log comment. The log comment will have a syntax of 'type : msg'.
     * @throws CADoesntExistsException if a referenced CA does not exist.
     * @throws AuthorizationDeniedException if the administrators isn't authorized to log.
     */
    void customLog(AuthenticationToken authenticationToken, int level, String type, String caName, String username, String certificateSn, String msg, EventType event) 
            throws AuthorizationDeniedException, CADoesntExistsException;
}
