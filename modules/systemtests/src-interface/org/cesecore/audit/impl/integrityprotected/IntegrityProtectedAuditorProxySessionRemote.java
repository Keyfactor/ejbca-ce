/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.audit.impl.integrityprotected;

import java.util.Date;
import java.util.Properties;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;

/**
 * Acts as a proxy for IntegrityProtectedAuditorSessionBean
 * 
 * @version $Id$
 *
 */
@Remote
public interface IntegrityProtectedAuditorProxySessionRemote {

    int deleteRows(final AuthenticationToken token, final Date timestamp, final Properties properties) throws AuthorizationDeniedException;

}