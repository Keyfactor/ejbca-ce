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
package org.cesecore.keys.util;

import java.security.Provider;

import org.ejbca.cvc.CVCProvider;

import com.keyfactor.util.crypto.provider.CryptoProvider;

/**
 *
 */
public class CvcCryptoProvider implements CryptoProvider {

    @Override
    public Provider getProvider() {
        return new CVCProvider();
    }

    @Override
    public String getErrorMessage() {
        return "CVC provider can not be installed, CVC certificate will not work: ";
    }

    @Override
    public String getName() {
        return "CVC";
    }

}
