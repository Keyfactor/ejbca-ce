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

import java.util.Collection;
import java.util.HashMap;
import java.util.Set;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
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
     * Revokes the certificate in the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisher IDs.
     * @throws AuthorizationDeniedException if access was denied to the CA issuing cert
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    void revokeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, CertificateDataWrapper certificateWrapper,
            String username, String userDN, String cafp, int type, int reason, long revocationDate, String tag,
            int certificateProfileId, long lastUpdate) throws AuthorizationDeniedException;

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
     * @return the publisher ID
     * 
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    int addPublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException;

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void addPublisher(AuthenticationToken admin, int id, String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException;

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
     * Retrieves a Set of all Publisher IDs 
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @return Set of IDs (Integer)
     */
    Set<Integer> getAllPublisherIds();

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
     * Returns a publishers name given its id.
     * @return the name or null if id does not exist
     */
    String getPublisherName(int id);

    /**
     * Use from Healthcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * @return an error message or an empty String if all are ok.
     */
    String testAllConnections(); // NOPMD: this is not a JUnit test
}
