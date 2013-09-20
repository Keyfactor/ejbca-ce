/*************************************************************************
 *                                                                       *
 *  CESeCore: CE Security Core                                           *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/
package org.cesecore.certificates.ocsp.exception;

/**
 * A exception wrapper to cover different BouncyCastle provider errors.
 * 
 * @version $Id$
 *
 */
public class CryptoProviderException extends RuntimeException {


    private static final long serialVersionUID = -3334600937753128052L;
    
    public CryptoProviderException() {
        super();
    }

    public CryptoProviderException(String msg, Throwable t) {
        super(msg, t);
    }

    public CryptoProviderException(String msg) {
        super(msg);
    }

    public CryptoProviderException(Throwable msg) {
        super(msg);
    }


}
