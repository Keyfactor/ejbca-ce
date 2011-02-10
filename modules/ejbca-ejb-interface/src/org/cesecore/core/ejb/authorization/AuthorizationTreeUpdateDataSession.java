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
package org.cesecore.core.ejb.authorization;

import org.ejbca.core.ejb.authorization.AuthorizationTreeUpdateData;

/**
 * @version $Id$
 */
public interface AuthorizationTreeUpdateDataSession {

    /** Returns a reference to the AuthorizationTreeUpdateData. */
    AuthorizationTreeUpdateData getAuthorizationTreeUpdateData();
    
    /**
     * Method incrementing the authorization tree update number and thereby
     * signaling to other beans that they should reconstruct their access trees.
     */
    public void signalForAuthorizationTreeUpdate();
}
