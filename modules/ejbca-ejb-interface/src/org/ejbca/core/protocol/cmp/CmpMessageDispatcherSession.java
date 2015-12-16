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

import java.io.IOException;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.request.ResponseMessage;

/**
 * @version $Id$
 */
public interface CmpMessageDispatcherSession {
    
    /** Handles a received CMP messages by dispatching it to the proper message handler after figuring out what type of CMP message it is.
     * The message may have been received by any transport protocol, and is passed here in it's binary ASN.1 form.
     * 
     * @param admin the administrator performing the call
     * @param derObject DER encoded CMP message as a byte array, length limit of this byte array must be enforced by caller
     * @param confAlias the cmp alias we want to use for this request
     * @return IResponseMessage containing the CMP response message or null if there is no message to send back or some internal error has occurred
     * @throws IOException if the message can not be parsed
     * @throws NoSuchAliasException if the confAlias does not exist among configured cmp aliases
     */
	ResponseMessage dispatch(AuthenticationToken admin, byte[] derObject, String confAlias) throws IOException, NoSuchAliasException;
}
