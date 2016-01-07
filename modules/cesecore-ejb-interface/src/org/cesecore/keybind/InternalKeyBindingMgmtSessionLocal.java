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
package org.cesecore.keybind;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;

import javax.ejb.Local;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;

/**
 * @see InternalKeyBindingMgmtSession
 * @version $Id$
 */
@Local
public interface InternalKeyBindingMgmtSessionLocal extends InternalKeyBindingMgmtSession {
       
    /**
     * Returns a list of all internal key bindings of a certain type, as {@link InternalKeyBindingInfo}s
     * 
     * @param internalKeyBindingType the key binding type
     * @return a list of all internal key bindings of that type, as {@link InternalKeyBindingInfo}s
     */
    List<InternalKeyBindingInfo> getAllInternalKeyBindingInfos(String internalKeyBindingType);
    
    /**
     * Internal (local only) method to get keybinding info without logging the authorization check
     * (the auth check is performed though).
     * 
     * @see getInternalKeyBindingInfo
     */
    InternalKeyBindingInfo getInternalKeyBindingInfoNoLog(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Get a reference to a cached InternalKeyBinding object that MAY NOT be modified.
     * 
     * @param authenticationToken is the authentication token
     * @param internalKeyBindingId is the identifier of the InternalKeyBinding
     * @return the InternalKeyBinding for the requested Id or null if none was found
     * @throws AuthorizationDeniedException if the authentication token was not authorized to fetch the requested InternalKeyBinding
     */
    InternalKeyBinding getInternalKeyBindingReference(AuthenticationToken authenticationToken, int internalKeyBindingId) throws AuthorizationDeniedException;

    /**
     * Returns a collection of the trusted certificates defined in internalKeyBinding along with their issuers' certificate chains.
     * 
     * - If the list of trusted certificates in internalKeyBinding contains certificate serial number(s), only the certificates with these specific serial numbers
     *   are trusted
     * - If only trusted CAs are specified in internalKeyBinding, all certificates issued by the specified CAs will be trusted.
     * - If the list of trusted certificates in internalKeyBinding is empty, all certificates issued by all CAs known to this instance of EJBCA are trusted
     * - If the list of trusted certificates in internalKeyBinding is null, no certificates will be trusted.
     *
     * 
     * @param authenticationToken
     * @param internalKeyBinding
     * @return a collection of the trusted certificates along with their issuers' certificate chains or null if no trusted certificates or CAs are specified
     * @throws CADoesntExistsException
     */
    List< Collection<X509Certificate> > getListOfTrustedCertificates(InternalKeyBinding internalKeyBinding) throws CADoesntExistsException;
}
