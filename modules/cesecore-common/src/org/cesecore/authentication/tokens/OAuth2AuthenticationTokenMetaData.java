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
package org.cesecore.authentication.tokens;

import java.util.Arrays;

import org.cesecore.authorization.user.matchvalues.OAuth2AccessMatchValue;

/**
 * Meta data definition and ServiceLoader marker for {@link org.cesecore.authentication.tokens.OAuth2AuthenticationToken}.
 *
 * @version $Id$
 */
public class OAuth2AuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    public static final String TOKEN_TYPE = "OAuth2AuthenticationToken";

    public OAuth2AuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(OAuth2AccessMatchValue.values()), true);
    }
}
