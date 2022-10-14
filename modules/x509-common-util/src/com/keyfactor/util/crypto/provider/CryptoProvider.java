/*************************************************************************
 *                                                                       *
 * Keyfactor Commons                                                     *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package com.keyfactor.util.crypto.provider;

import java.security.Provider;

/**
 * Marker interface for externally defined providers. To add a provider, implement this class and make sure that 
 * the jar has this interface in its manifest file.
 * 
 */
public interface CryptoProvider {

    Provider getProvider();
    
    String getErrorMessage();
    
    String getName();
}
