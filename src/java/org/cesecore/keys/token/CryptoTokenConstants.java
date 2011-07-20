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
package org.cesecore.keys.token;

/**
 * Based on EJBCA version: 
 *      CATokenConstants.java 8629 2010-02-08 15:47:15Z jeklund
 * CESeCore version:
 *      CryptoTokenConstants.java 389 2011-03-01 14:56:15Z tomas
 * 
 * @version $Id$
 */
public final class CryptoTokenConstants {

    /** constants needed for soft crypto tokens */
    protected static final String SIGNKEYSPEC       = "SIGNKEYSPEC";
    protected static final String ENCKEYSPEC        = "ENCKEYSPEC";
    protected static final String SIGNKEYALGORITHM  = "SIGNKEYALGORITHM";
    protected static final String ENCKEYALGORITHM   = "ENCKEYALGORITHM";
    protected static final String KEYSTORE          = "KEYSTORE";

}
