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
package org.ejbca.core.model.era;

import javax.ejb.Remote;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.core.protocol.cmp.CmpMessageDispatcherSessionLocal;
import org.ejbca.core.protocol.cmp.NoSuchAliasException;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;

/**
 * @version $Id$
 *
 */
@Remote
public interface TestRaMasterApiProxySessionRemote {

    /**
     * Adds (end entity) user.
     * @param admin authentication token
     * @param endEntity end entity data as EndEntityInformation object
     * @param clearpwd 
     * @throws AuthorizationDeniedException
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process
     * @throws WaitingForApprovalException if approval is required to finalize the adding of the end entity
     * @return true if used has been added, false otherwise
     */
    boolean addUser(AuthenticationToken authenticationToken, EndEntityInformation endEntity, boolean clearpwd)
            throws AuthorizationDeniedException, EjbcaException, WaitingForApprovalException;

    /**
     * Dispatch CMP request over RaMasterApi.
     * 
     * Basic ASN.1 validation is performed at a proxy to increase the protection of a CA slightly.
     * 
     * Will use a local AlwaysAllowToken, which should fail if used remotely. 
     * 
     * @param authenticationToken the origin of the request
     * @param pkiMessageBytes the ASN.1 encoded CMP message request bytes
     * @param cmpConfigurationAlias the requested CA configuration that should handle the request.
     * @return the CMP response ASN.1 (success or error) message as a byte array or null if no processing could take place
     * @see CmpMessageDispatcherSessionLocal#dispatchRequest(AuthenticationToken, byte[], String)
     * @since RA Master API version 1 (EJBCA 6.8.0)
     */
    byte[] cmpDispatch(byte[] pkiMessageBytes, String cmpConfigurationAlias) throws NoSuchAliasException;
    
    /**
     * 
     * @param apiType the implementation of RaMasterApi to check for 
     * @return returns true if an API of a certain type is available
     */
    boolean isBackendAvailable(Class<? extends RaMasterApi> apiType);
    
    /**
     * Generates a certificate. This variant is used from the Web Service interface.
     * @param authenticationToken authentication token.
     * @param userdata end entity information, encoded as a UserDataVOWS (web service value object). Must have been enriched by the WS setUserDataVOWS/enrichUserDataWithRawSubjectDn methods.
     * @param requestData see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param requestType see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param hardTokenSN see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @param responseType see {@link org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest IEjbcaWS.certificateRequest()}
     * @return certificate binary data. If the certificate request is invalid, then this can in certain cases be null. 
     * @throws AuthorizationDeniedException if not authorized to create a certificate with the given CA or the profiles
     * @throws ApprovalException if the request requires approval
     * @throws EjbcaException if an EJBCA exception with an error code has occurred during the process, for example non-existent CA
     * @throws EndEntityProfileValidationException if the certificate does not match the profiles.
     * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#certificateRequest
     */
    byte[] createCertificateWS(final AuthenticationToken authenticationToken, final UserDataVOWS userdata, final String requestData, final int requestType,
            final String hardTokenSN, final String responseType) throws AuthorizationDeniedException, ApprovalException, EjbcaException,
            EndEntityProfileValidationException;
    
}
