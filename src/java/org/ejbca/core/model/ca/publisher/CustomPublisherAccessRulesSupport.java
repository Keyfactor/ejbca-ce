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
package org.ejbca.core.model.ca.publisher;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * A publisher that implements this interface contains additional access rules
 * 
 * @version $Id$
 */
public interface CustomPublisherAccessRulesSupport {

    /** @return true if admin is authorized to view this publisher. */
    boolean isAuthorizedToPublisher(AuthenticationToken authenticationToken);
}
