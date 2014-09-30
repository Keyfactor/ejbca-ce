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
package org.ejbca.core.ejb.ra;

import java.util.AbstractMap;

import javax.ejb.Local;

import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * @version $Id$
 *
 */
@Local
public interface EndEntityAccessSessionLocal extends EndEntityAccessSession {

    /**
     * Using some heuristics and tarot cards, returns which algorithm and method that's been used to hash this user's password.
     * 
     * @param username the user name of the sought user.
     * @return the password and algorithm for the sought user. If algorithm is hashed, so will the password be, otherwise cleartext. Null if user was not found.
     * @throws NotFoundException 
     */
    AbstractMap.SimpleEntry<String, SupportedPasswordHashAlgorithm> getPasswordAndHashAlgorithmForUser(String username) throws NotFoundException;
}
