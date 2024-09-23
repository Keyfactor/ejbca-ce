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

import jakarta.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;

/*
Remote interface to allow access to local methods from system tests
 */
@Remote
public interface AdminPreferenceProxySessionRemote {

    /**
     * Deletes the admin preference belonging to the given administrator.
     *  @param token Authentication token of the administrator
     */
    void deleteAdminPreferences(final AuthenticationToken token);

}
