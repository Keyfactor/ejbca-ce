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

package org.ejbca.core.protocol.ocsp.standalonesession;


/**
 * Holds information about a provider.
 * Used to be able to reload a provider when a HSM has stoped working.
 * For other sub classes but {@link P11ProviderHandler} nothing is done at reload when {@link #reload()} is called.
 * 
 * @author primelars
 * @version  $Id$
 */
interface ProviderHandler {
    /**
     * Gets the name of the provider.
     * @return the name. null if the provider is not working (reloading).
     */
    String getProviderName();
    /**
     * Must be called for all {@link PrivateKeyContainer} objects using this object.
     * @param keyContainer {@link PrivateKeyContainer} to be updated at reload
     */
    void addKeyContainer(PrivateKeyContainer keyContainer);
    /**
     * Start a threads that tries to reload the provider until it is done or does nothing if reloading does't help.
     */
    void reload();
}