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

import java.util.Collection;

import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;
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
     * @return true if sucessfull result on all given publishers
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCertificate(org.ejbca.core.model.log.Admin admin, Collection<Integer> publisherids, java.security.cert.Certificate incert,
            java.lang.String username, java.lang.String password, java.lang.String userDN, java.lang.String cafp, int status, int type, long revocationDate,
            int revocationReason, java.lang.String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation);
    
    /**
     * Revokes the certificate in the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void revokeCertificate(org.ejbca.core.model.log.Admin admin, java.util.Collection<Integer> publisherids, java.security.cert.Certificate cert,
            java.lang.String username, java.lang.String userDN, java.lang.String cafp, int type, int reason, long revocationDate, java.lang.String tag,
            int certificateProfileId, long lastUpdate);

    /**
     * Stores the crl to the given collection of publishers. See BasePublisher
     * class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisherids.
     * @return true if sucessfull result on all given publishers
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public boolean storeCRL(org.ejbca.core.model.log.Admin admin, java.util.Collection<Integer> publisherids, byte[] incrl, java.lang.String cafp,
                            int number, java.lang.String userDN);

    /**
     * Test the connection to of a publisher
     * 
     * @param publisherid
     *            the id of the publisher to test.
     * @throws PublisherConnectionException if connection test with publisher fails.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    public void testConnection(org.ejbca.core.model.log.Admin admin, int publisherid) throws PublisherConnectionException;

    /**
     * Adds a publisher to the database.
     * 
     * @throws PublisherExistsException
     *             if hard token already exists.
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void addPublisher(org.ejbca.core.model.log.Admin admin, java.lang.String name, org.ejbca.core.model.ca.publisher.BasePublisher publisher)
            throws PublisherExistsException;

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     * 
     * @throws PublisherExistsException
     *             if publisher already exists.
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void addPublisher(org.ejbca.core.model.log.Admin admin, int id, java.lang.String name, org.ejbca.core.model.ca.publisher.BasePublisher publisher)
            throws PublisherExistsException;

    /**
     * Updates publisher data
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void changePublisher(org.ejbca.core.model.log.Admin admin, java.lang.String name, org.ejbca.core.model.ca.publisher.BasePublisher publisher);

    /**
     * Adds a publisher with the same content as the original.
     * 
     * @throws PublisherExistsException
     *             if publisher already exists.
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void clonePublisher(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname);

    /**
     * Removes a publisher from the database.
     * 
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void removePublisher(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Renames a publisher
     * 
     * @throws PublisherExistsException
     *             if publisher already exists.
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public void renamePublisher(org.ejbca.core.model.log.Admin admin, java.lang.String oldname, java.lang.String newname)
            throws PublisherExistsException;

    /**
     * Retrives a Collection of id:s (Integer) for all authorized publishers if
     * the Admin has the SUPERADMIN role. Use
     * CAAdminSession.getAuthorizedPublisherIds to get the list for any
     * administrator.
     * 
     * @param admin Should be an Admin with superadmin credentials
     * @return Collection of id:s (Integer)
     * @throws AuthorizationDeniedException if the admin does not have superadmin credentials
     */
    public java.util.Collection<Integer> getAllPublisherIds(org.ejbca.core.model.log.Admin admin) throws AuthorizationDeniedException;

    /**
     * Method creating a hashmap mapping publisher id (Integer) to publisher
     * name (String).
     */
    public java.util.HashMap<Integer,String> getPublisherIdToNameMap(org.ejbca.core.model.log.Admin admin);

    /**
     * Retrives a named publisher.
     * 
     * @return a BasePublisher or null of a publisher with the given id does not
     *         exist
     */
    public org.ejbca.core.model.ca.publisher.BasePublisher getPublisher(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Finds a publisher by id.
     * 
     * @return a BasePublisher or null of a publisher with the given id does not
     *         exist
     */
    public org.ejbca.core.model.ca.publisher.BasePublisher getPublisher(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Help method used by publisher proxys to indicate if it is time to update
     * it's data.
     */
    public int getPublisherUpdateCount(org.ejbca.core.model.log.Admin admin, int publisherid);

    /**
     * Returns a publisher id, given it's publishers name
     * 
     * @return the id or 0 if the publisher cannot be found.
     */
    public int getPublisherId(org.ejbca.core.model.log.Admin admin, java.lang.String name);

    /**
     * Returns a publishers name given its id.
     * 
     * @return the name or null if id doesnt exists
     * @throws javax.ejb.EJBException
     *             if a communication or other error occurs.
     */
    public String getPublisherName(org.ejbca.core.model.log.Admin admin, int id);

    /**
     * Use from Healtcheck only! Test connection for all publishers. No
     * authorization checks are performed.
     * 
     * @return an error message or an empty String if all are ok.
     * 
     * TODO: Move this to local interface!
     */
    public java.lang.String testAllConnections();
}
