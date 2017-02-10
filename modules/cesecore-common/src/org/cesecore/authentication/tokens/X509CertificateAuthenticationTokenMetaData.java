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
package org.cesecore.authentication.tokens;

import java.util.Arrays;

import org.cesecore.authorization.user.matchvalues.X500PrincipalAccessMatchValue;

/**
 * Meta data definition and ServiceLoader marker for {@link org.cesecore.authentication.tokens.X509CertificateAuthenticationToken}.
 * 
 * @version $Id$
 */
public class X509CertificateAuthenticationTokenMetaData extends AuthenticationTokenMetaDataBase {

    public static final String TOKEN_TYPE = "CertificateAuthenticationToken";

    public X509CertificateAuthenticationTokenMetaData() {
        super(TOKEN_TYPE, Arrays.asList(X500PrincipalAccessMatchValue.values()), true);
    }
}
