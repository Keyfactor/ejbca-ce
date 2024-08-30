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
package org.ejbca;

import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;

import jakarta.ejb.Stateless;
import jakarta.ejb.TransactionAttribute;
import jakarta.ejb.TransactionAttributeType;

import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

/**
 *
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class PublicKeySerialisationSystemTestSessionBean implements PublicKeySerialisationSystemTestSessionRemote {

    @Override
    public PublicKey getKey() {     
        try {
            return KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA).getPublic();
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("RSA should be a known algorithm", e);
        }
    }

}
