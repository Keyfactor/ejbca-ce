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
package org.ejbca.core.protocol.est;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.certificate.request.PKCS10RequestMessage;
import org.cesecore.certificates.certificate.request.RequestMessage;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;

/**
 * @version $Id: CmpMessageDispatcherSessionLocal.java 25797 2017-05-04 15:52:00Z jeklund $
 */
@Local
public interface EstOperationsSessionLocal extends EstOperationsSession {
    public byte[] getCacerts(AuthenticationToken authenticationToken, String estConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException;
    
    public byte[] simpleEnroll(AuthenticationToken authenticationToken, PKCS10RequestMessage csr, String estConfigurationAlias) throws NoSuchAliasException, CADoesntExistsException, AuthorizationDeniedException;
}
