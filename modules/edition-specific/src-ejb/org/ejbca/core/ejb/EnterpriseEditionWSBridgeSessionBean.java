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
package org.ejbca.core.ejb;

import java.util.HashMap;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * JEE5 EJB lookup helper.
 * 
 * @version $Id: EnterpriseEditionEjbBridgeSessionBean.java 20647 2015-02-10 11:07:47Z aveen4711 $
 */
@Stateless
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class EnterpriseEditionWSBridgeSessionBean implements EnterpriseEditionWSBridgeSessionLocal {

    @Override
    public void createCryptoToken(AuthenticationToken admin, String tokenName, String tokenType, String activationPin, boolean autoActivate, boolean exportKey, 
            String pkcs11LibFilename, String pkcs11SlotLabelType, String pkcs11SlotPropertyValue,
            HashMap<String, String> PKCS11AttributeData) throws UnsupportedMethodException {
        throw new UnsupportedMethodException("This method can only be used in Enterprise edition.");
    }
    
    @Override
    public void generateCryptoTokenKeys(AuthenticationToken admin, String cryptoTokenName, String keyPairAlias, String keySpecification) 
            throws UnsupportedMethodException {
        throw new UnsupportedMethodException("This method can only be used in Enterprise edition.");
    }
}