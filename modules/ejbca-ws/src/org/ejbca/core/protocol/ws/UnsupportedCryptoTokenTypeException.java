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

package org.ejbca.core.protocol.ws;

import javax.xml.ws.WebFault;

import org.cesecore.ErrorCode;
import org.ejbca.core.EjbcaException;

/**
 * Thrown when the crypto token type is unrecognized. Recognized crypto token types are: SofCryptoToken and PKCS11CryptoToken. 
 *
 * @version $Id$
 *
 */
@WebFault
public class UnsupportedCryptoTokenTypeException extends EjbcaException {




    private static final long serialVersionUID = -4699494647692559227L;

    /**
     * @param message with more information what is wrong
     */
    public UnsupportedCryptoTokenTypeException(String m) {
        super(ErrorCode.NOT_SUPPORTED_TOKEN_TYPE, m);
    }
}
