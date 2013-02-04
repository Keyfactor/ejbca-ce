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

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.ejbca.core.model.ca.publisher.BasePublisher;


/**
 * Interface for publisher operations
 *
 * @version $Id$
 */
public interface PublisherSession {

    /**
     * @return a BasePublisher or null of a publisher with the given id does not
     *         exist. Uses cache to get the object as quickly as possible.
     */
    BasePublisher getPublisher(int id);
    
    /**
     * @return a BasePublisher or null of a publisher with the given name does
     *         not exist. Uses cache to get the object as quickly as possible.
     */
    BasePublisher getPublisher(String name);

    /** Updates publisher data. 
     * @throws AuthorizationDeniedException */
    void changePublisher(AuthenticationToken admin, String name, BasePublisher publisher) throws AuthorizationDeniedException;

    /**
     * Stores the certificate to the given collection of publishers. See
     * BasePublisher class for further documentation about function
     * 
     * @param publisherids
     *            a Collection (Integer) of publisher IDs.
     * @return true if successful result on all given publishers
     * @throws AuthorizationDeniedException if access is denied to the CA issuing incert
     * @see org.ejbca.core.model.ca.publisher.BasePublisher
     */
    boolean storeCertificate(AuthenticationToken admin, Collection<Integer> publisherids, Certificate incert,
            String username, String password, String userDN, String cafp, int status, int type, long revocationDate,
            int revocationReason, String tag, int certificateProfileId, long lastUpdate,
            ExtendedInformation extendedinformation) throws AuthorizationDeniedException;
    
    
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
