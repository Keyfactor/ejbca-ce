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
package org.cesecore.authentication;

import java.security.Principal;
import java.util.Set;

import org.cesecore.authentication.tokens.AuthenticationSubject;

/**
 * Trivial Subject stub for testing purposes.
 * 
 * @version $Id$
 *
 */
public class SimpleSubject extends AuthenticationSubject {

 
    private static final long serialVersionUID = 2345444099532544258L;

    public SimpleSubject(Set<Principal> principals, Set<?> credentials) {
        super(principals, credentials);
    }
}
