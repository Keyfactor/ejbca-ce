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
package org.ejbca.core.protocol.scep;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.ejbca.config.ScepConfiguration;
import org.ejbca.core.model.approval.WaitingForApprovalException;

/**
 * Interface for SCEP plugins which perform operations
 * 
 *
 */
public interface ScepOperationPlugin {

    /**
     * Performs an operation on this extension
     * 
     * @param authenticationToken an authentication token for any operations that may require one
     * @param reqmsg the requestmessage to perform operations on
     * @param scepConfig the SCEP configuration, if required
     * @param alias alias of the SCEP configuration
     * @return true if the operation succeeded 
     * @throws AuthorizationDeniedException if the request was sent to the wrong CA, the current token does not have access to that CA, or the RA password being used was incorrect
     * @throws WaitingForApprovalException if the request was processed but requires approval
     */
    boolean performOperation(AuthenticationToken authenticationToken, ScepRequestMessage reqmsg, final ScepConfiguration scepConfig,
            final String alias) throws AuthorizationDeniedException, WaitingForApprovalException;
}
