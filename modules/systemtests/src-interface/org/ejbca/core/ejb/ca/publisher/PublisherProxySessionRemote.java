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

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherConnectionException;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;

/**
 * @version $Id$
 *
 */
@Remote
public interface PublisherProxySessionRemote {

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
     * @throws PublisherExistsException 
     * @throws AuthorizationDeniedException 
     * @throws PublisherDoesntExistsException 
     * @throws PublisherExistsException if publisher already exists.
     */
    void clonePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherDoesntExistsException, AuthorizationDeniedException, PublisherExistsException;
    
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
     * Removes publisher data. Ignores if there are any references to the publisher from CA, certificate profiles
     * or Multi Group Publishers, just goes ahead and removes it.
     */
    void removePublisherInternal(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Renames a publisher.
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException 
     */
    void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException;
    
    /**
     * Test the connection to of a publisher
     * 
     * @param publisherid
     *            the id of the publisher to test.
     * @throws PublisherConnectionException if connection test with publisher fails.
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    void testConnection(int publisherid) throws PublisherConnectionException;
    
    /**
     * Makes sure that no Publishers are cached to ensure that we read from database
     * next time we try to access it.
     */
    void flushPublisherCache();

    /** Change a Publisher without affecting the cache */
    void internalChangePublisherNoFlushCache(String name, BasePublisher publisher)
            throws AuthorizationDeniedException; 
    
    int adhocUpgradeTo6_3_1_1();
    

}
