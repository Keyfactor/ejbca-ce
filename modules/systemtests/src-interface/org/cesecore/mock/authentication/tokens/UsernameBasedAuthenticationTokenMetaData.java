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
package org.cesecore.mock.authentication.tokens;

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationTokenMetaDataBase;

/**
 * Meta data definition and ServiceLoader marker for {@link org.cesecore.mock.authentication.tokens.UsernameBasedAuthenticationToken}.
 * 
 * @version $Id$
 */
public class UsernameBasedAuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    public static final String TOKEN_TYPE = "UsernameBasedAuthenticationToken";
    
    public UsernameBasedAuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(UsernameAccessMatchValue.values()), false);
    }
}
