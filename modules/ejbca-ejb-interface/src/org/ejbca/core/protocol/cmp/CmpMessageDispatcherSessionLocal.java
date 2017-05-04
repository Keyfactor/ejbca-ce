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
package org.ejbca.core.protocol.cmp;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * @version $Id$
 */
@Local
public interface CmpMessageDispatcherSessionLocal extends CmpMessageDispatcherSession {

    /**
     * Handles a received CMP messages by dispatching it to the proper message handler after figuring out what type of CMP message it is.
     * The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
     * 
     * @param authenticationToken identifier of the CMP call's origin
     * @param pkiMessageBytes DER encoded CMP message as a byte array, length limit of this byte array must be enforced by caller
     * @param cmpConfigurationAlias the CMP configuration alias that has been requested to by the caller
     * @return the ASN.1 encoded CMP response message as a byte array or null if there is no message to send back or some internal error has occurred
     * @throws NoSuchAliasException if cmpConfigurationAlias is unknown
     */
    byte[] dispatchRequest(AuthenticationToken authenticationToken, byte[] pkiMessageBytes, String cmpConfigurationAlias) throws NoSuchAliasException;

}
