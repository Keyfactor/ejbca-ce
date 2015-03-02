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

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.util.KeyTools;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "PublicKeySerialisationTestSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class PublicKeySerialisationTestSessionBean implements PublicKeySerialisationTestSessionRemote {

    @Override
    public PublicKey getKey() {     
        try {
            return KeyTools.genKeys("512", AlgorithmConstants.KEYALGORITHM_RSA).getPublic();
        } catch (InvalidAlgorithmParameterException e) {
            throw new IllegalStateException("RSA should be a known algorithm", e);
        }
    }

}
