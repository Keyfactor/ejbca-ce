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
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.certificate.CertificateDataWrapper;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ca.publisher.PublisherDoesntExistsException;
import org.ejbca.core.model.ca.publisher.PublisherExistsException;


/**
 * Interface for publisher operations
 *
 * @version $Id$
 */
public interface PublisherSession {

    /**
     * @return a BasePublisher or null if a publisher with the given id does not
     *         exist. Uses cache to get the object as quickly as possible.
     *         
     */
    BasePublisher getPublisher(int id);
    
    /**
     * @return a BasePublisher or null if a publisher with the given name does
     *         not exist. Uses cache to get the object as quickly as possible.
     */
    BasePublisher getPublisher(String name);
    
    /**
     * @return the name of the publisher with the given id, null if none was found.
     */
    String getPublisherName(int id);
    
    /**
     * @return the data hashmap of the publisher with the given id.
     * @throws PublisherDoesntExistsException if there's no publisher with the given id.
     */
    Map<?, ?> getPublisherData(int id) throws PublisherDoesntExistsException;

    /** @return mapping of publisher id (Integer) to publisher name (String). */
    HashMap<Integer,String> getPublisherIdToNameMap();

    /** @return mapping of publisher name (String) to publisher id (Integer). */
    HashMap<String, Integer> getPublisherNameToIdMap();

    /**
     * Adds a publisher to the database. Used for importing and exporting
     * profiles from xml-files.
     *
     * @param admin AuthenticationToken of admin.
     * @param id the publisher is.
     * @param name the name of the publisher to add.
     * @param publisher the publisher to add.
     *
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void addPublisher(AuthenticationToken admin, int id, String name, BasePublisher publisher) throws PublisherExistsException, AuthorizationDeniedException;

    /**
     * Adds a publisher to the database. Used where it's not possible to pass a BasePublisher object,
     * such as in the CLI tools (e.g. statedump).
     * 
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void addPublisherFromData(AuthenticationToken admin, int id, String name, Map<?, ?> data) throws PublisherExistsException, AuthorizationDeniedException;

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

    /**
     * Renames a publisher.
     * @throws PublisherExistsException if publisher already exists.
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher
     */
    void renamePublisher(AuthenticationToken admin, String oldname, String newname) throws PublisherExistsException, AuthorizationDeniedException;
    
    /** Updates publisher data.
     *  
     * @param admin AuthenticationToken of admin.
     * @param name the name of the publisher to change.
     * @param publisher the publisher to be added.
     * 
     * @throws AuthorizationDeniedException */
    void changePublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws AuthorizationDeniedException;

    /**
     * Removes a publisher. References to the publisher from CA, certificate profiles and Multi Group Publishers
     * are checked.
     * 
     * @param admin AuthenticationToken of admin.
     * @param name the name of the publisher to remove.
     * 
     * @throws AuthorizationDeniedException required access rights are ca_functionality/edit_publisher, or if references exist.
     */
    void removePublisher(AuthenticationToken admin, String name) throws AuthorizationDeniedException;

    /**
     * Stores the certificate to the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisher IDs.
     * @return true if successful result on all given publishers, if the publisher is configured to not publish the certificate 
     * (for example publishing an active certificate when the publisher only publishes revoked), true is still returned because 
     * the publishing operation succeeded even though the publisher did not publish the certificate.
     * @throws AuthorizationDeniedException if access is denied to the CA issuing incert
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    boolean storeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, CertificateDataWrapper certWrapper,
            String password, String userDN, ExtendedInformation extendedinformation) throws AuthorizationDeniedException;

    /**
     * Performs the same operation as the other storeCertificate method in this class, but performs a lookup for a CertificateData and Base64CertData object.
     * 
     * To avoid unnecessary database lookups, only use this method where the CertificateData object isn't immediately available. 
     */
    boolean storeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, String fingerprint,
            String password, String userDN, ExtendedInformation extendedinformation) throws AuthorizationDeniedException; 

    /**
     * Stores the CRL to the given collection of publishers. See BasePublisher
     * class for further documentation about function
     * 
     * @param publisherids a Collection (Integer) of publisherids.
     * @param issuerDn the issuer of this CRL
     * @return true if successful result on all given publishers
     * @throws AuthorizationDeniedException if access was denied to the CA matching userDN
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    boolean storeCRL(AuthenticationToken admin, Collection<Integer> publisherids, byte[] incrl, String cafp,
            int number, String issuerDn) throws AuthorizationDeniedException;
}
