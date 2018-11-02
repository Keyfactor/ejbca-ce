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
package org.ejbca.core.ejb.ca.publisher;

import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;

/**
 * Local interface for PublisherSession.
 * @version $Id$
 */
@Local
public interface PublisherSessionLocal extends PublisherSession {
    
    /**
     * Makes sure that no Publishers are cached to ensure that we read from database
     * next time we try to access it.
     */
    void flushPublisherCache(); 

    /**
     * Test the connection to of a publisher
     * 
     * @param publisherid
     *            the id of the publisher to test.
     * @throws PublisherConnectionException if connection test with publisher fails.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    void testConnection(int publisherid) throws PublisherConnectionException; // NOPMD: this is not a JUnit test

    /**
     * Retrieves a Map of all Publishers
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @return Map of BasePublishers mapped by ID
     */
    Map<Integer, BasePublisher> getAllPublishers();
    
    /**
     * Returns a Map of all Publishers. This method does not take into account if external scripts are disabled.
     */
    Map<Integer, BasePublisher> getAllPublishersInternal();

    /**
     * Help method used by publisher proxys to indicate if it is time to update
     * it's data.
     */
    int getPublisherUpdateCount(int publisherid);

    /**
     * Returns a publisher id, given it's publishers name
     * @return the id or 0 if the publisher cannot be found.
     */
    int getPublisherId(String name);

    /**
     * Use from Healthcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * @return an error message or an empty String if all are ok.
     */
    String testAllConnections(); // NOPMD: this is not a JUnit test

    /**
     * Removes publisher data. Ignores if there are any references to the publisher from CA, certificate profiles
     * or Multi Group Publishers, just goes ahead and removes it.
     * 
     * @param admin AuthenticationToken of admin.
     * @param name the name of the publisher to remove.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void removePublisherInternal(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Allows upgrade for Community Users to EJBCA 6.3.1.1 from previous versions of EJBCA by replacing the old 
     * VA publisher with a placeholder 
     * 
     * @return the number of upgraded publishers
     */
    int adhocUpgradeTo6_3_1_1();

    /** @return true if the old VA publisher is still present in the database and upgrade is needed. */
    boolean isOldVaPublisherPresent();
}
