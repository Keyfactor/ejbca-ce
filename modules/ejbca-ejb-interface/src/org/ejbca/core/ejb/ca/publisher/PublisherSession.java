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

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.ExtendedInformation;

/**
 * Interface for publisher operations
 *
 * @version $Id$
 */
public interface PublisherSession {

	/**
     * Stores the certificate to the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @return true if successful result on all given publishers
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(Admin admin, Collection<Integer> publisherids, Certificate incert,
            String username, String password, String userDN, String cafp, int status, int type, long revocationDate,
            int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation);
    
    /**
     * Revokes the certificate in the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void revokeCertificate(Admin admin, Collection<Integer> publisherids, Certificate cert,
            String username, String userDN, String cafp, int type, int reason, long revocationDate, String tag,
            int certificateProfileId, long lastUpdate);

    /**
     * Stores the CRL to the given collection of publishers. See BasePublisher
     * class for further documentation about function
     * 
     * @param publisherids a Collection (Integer) of publisherids.
     * @return true if successful result on all given publishers
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCRL(Admin admin, Collection<Integer> publisherids, byte[] incrl, java.lang.String cafp,
                            int number, String userDN);

    /**
     * Test the connection to of a publisher
     * 
     * @param publisherid
     *            the id of the publisher to test.
     * @throws PublisherConnectionException if connection test with publisher fails.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void testConnection(Admin admin, int publisherid) throws PublisherConnectionException;

    /**
     * Adds a publisher to the database.
     * @throws PublisherExistsException if hard token already exists.
     */
    public void addPublisher(Admin admin, String name, BasePublisher publisher) throws PublisherExistsException;

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws PublisherExistsException if publisher already exists.
     */
    public void addPublisher(Admin admin, int id, String name, BasePublisher publisher) throws PublisherExistsException;

    /** Updates publisher data. */
    public void changePublisher(Admin admin, String name, BasePublisher publisher);

    /**
     * Adds a publisher with the same content as the original.
     * @throws PublisherExistsException if publisher already exists.
     */
    public void clonePublisher(Admin admin, String oldname, String newname);

    /** Removes a publisher from the database. */
    public void removePublisher(Admin admin, String name);

    /**
     * Renames a publisher.
     * @throws PublisherExistsException if publisher already exists.
     */
    public void renamePublisher(Admin admin, String oldname, String newname) throws PublisherExistsException;

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
    public Collection<Integer> getAllPublisherIds(Admin admin) throws AuthorizationDeniedException;

    /** @return mapping of publisher id (Integer) to publisher name (String). */
    public HashMap<Integer,String> getPublisherIdToNameMap(Admin admin);

    /**@return a BasePublisher or null of a publisher with the given name does not exist */
    public BasePublisher getPublisher(Admin admin, String name);

    /**@return a BasePublisher or null of a publisher with the given id does not exist */
    public BasePublisher getPublisher(Admin admin, int id);

    /**
     * Help method used by publisher proxys to indicate if it is time to update
     * it's data.
     */
    public int getPublisherUpdateCount(Admin admin, int publisherid);

    /**
     * Returns a publisher id, given it's publishers name
     * @return the id or 0 if the publisher cannot be found.
     */
    public int getPublisherId(Admin admin, String name);

    /**
     * Returns a publishers name given its id.
     * @return the name or null if id doesn't exists
     */
    public String getPublisherName(Admin admin, int id);

    /**
     * Use from Healtcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * @return an error message or an empty String if all are ok.
     */
    // TODO: Move this to local interface!
    public java.lang.String testAllConnections();
}
