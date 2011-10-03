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
package org.ejbca.core.ejb.ca.publisher;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.HashMap;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

/**
 * Local interface for PublisherSession.
 * @version $Id$
 */
@Local
public interface PublisherSessionLocal extends PublisherSession {
    
    /**
     * Revokes the certificate in the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisher IDs.
     * @throws AuthorizationDeniedException if access was denied to the CA issuing cert
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    void revokeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, Certificate cert,
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
    void testConnection(AuthenticationToken admin, int publisherid) throws PublisherConnectionException;

    /**
     * Adds a publisher to the database.
     * @throws PublisherExistsException if hard token already exists.
     */
    void addPublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws PublisherExistsException;

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws PublisherExistsException if publisher already exists.
     */
    void addPublisher(AuthenticationToken admin, int id, String name, BasePublisher publisher) throws PublisherExistsException;

    /** Updates publisher data. */
    void changePublisher(AuthenticationToken admin, String name, BasePublisher publisher);

    /**
     * Adds a publisher with the same content as the original.
     * @throws PublisherExistsException if publisher already exists.
     */
    void clonePublisher(AuthenticationToken admin, String oldname, String newname);

    /** Removes a publisher from the database. */
    void removePublisher(AuthenticationToken admin, String name);

    /**
     * Renames a publisher.
     * @throws PublisherExistsException if publisher already exists.
     */
    void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException;

    /**
     * Retrieves a Collection of id:s (Integer) for all authorized publishers if
     * the Admin has the SUPERADMIN role.
     * 
     * Use CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @param admin Should be an Admin with superadmin credentials
     * @return Collection of id:s (Integer)
     * @throws AuthorizationDeniedException
     *             if the admin does not have superadmin credentials
     */
    Collection<Integer> getAllPublisherIds(AuthenticationToken admin) throws AuthorizationDeniedException;

    /** @return mapping of publisher id (Integer) to publisher name (String). */
    HashMap<Integer,String> getPublisherIdToNameMap(AuthenticationToken admin);

    /**
     * Help method used by publisher proxys to indicate if it is time to update
     * it's data.
     */
    int getPublisherUpdateCount(AuthenticationToken admin, int publisherid);

    /**
     * Returns a publisher id, given it's publishers name
     * @return the id or 0 if the publisher cannot be found.
     */
    int getPublisherId(AuthenticationToken admin, String name);

    /**
     * Returns a publishers name given its id.
     * @return the name or null if id does not exist
     */
    String getPublisherName(AuthenticationToken admin, int id);

    /**
     * Use from Healtcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * @return an error message or an empty String if all are ok.
     */
    String testAllConnections();
}
