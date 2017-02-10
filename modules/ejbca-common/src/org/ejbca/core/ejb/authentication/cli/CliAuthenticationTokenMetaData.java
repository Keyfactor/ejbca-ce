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
package org.ejbca.core.ejb.authentication.cli;

import java.util.Arrays;

import org.cesecore.authentication.tokens.AuthenticationTokenMetaDataBase;

/**
 * Meta data definition and ServiceLoader marker for {@link org.ejbca.core.ejb.authentication.cli.CliAuthenticationToken}.
 * 
 * @version $Id$
 */
public class CliAuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    public static final String TOKEN_TYPE = "CliAuthenticationToken";

    public CliAuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(CliUserAccessMatchValue.USERNAME), true);
    }
}
