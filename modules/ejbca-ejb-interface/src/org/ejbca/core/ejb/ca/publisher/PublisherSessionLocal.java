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

import java.util.HashMap;
import java.util.Map;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

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
     * Adds a publisher to the database.
     * 
     * @param admin AuthenticationToken of admin
     * @param name the name of the publisher to add.
     * @param publisher the publisher to add
     * @return the publisher ID as added
     * 
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    int addPublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException;

    /**
     * Adds a publisher with the same content as the original.
     * @throws PublisherDoesntExistsException if publisher does not exist
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     * @throws PublisherExistsException if publisher already exists.
     */
    void clonePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherDoesntExistsException, AuthorizationDeniedException, PublisherExistsException;

    /** Removes a publisher from the database. 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void removePublisher(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Renames a publisher.
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException;

    /**
     * Retrieves a Map of all Publishers
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @return Map of BasePublishers mapped by ID
     */
    Map<Integer, BasePublisher> getAllPublishers();

    /** @return mapping of publisher id (Integer) to publisher name (String). */
    HashMap<Integer,String> getPublisherIdToNameMap();

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
     * Allows upgrade for Community Users to EJBCA 6.3.1.1 from previous versions of EJBCA by replacing the old 
     * VA publisher with a placeholder 
     * 
     * @return the number of upgraded publishers
     */
    int adhocUpgradeTo6_3_1_1();
}
