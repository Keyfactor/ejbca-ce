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

import java.io.Serializable;

/**
 * This is a callback interface that provides a method of authentication for a subject. It should be implemented by whatever EJB Session bean (outside
 * of CESeCore) that perform local authentication.
 * 
 * Based on cesecore version:
 *      AuthenticationProvider.java 509 2011-03-10 13:48:44Z mikek
 * 
 * @version $Id$
 * 
 */
public interface AuthenticationProvider extends Serializable {

    static final String DEFAULT_DN = "C=SE,O=Test,CN=Test"; // default
    
    /**
     * Implement this method to authenticate a subject using its principals and credentials. The method of doing this operation is entirely up to
     * whoever implements this API. The returned AuthenticationToken should only contain those principals and credentials which were actually used in
     * the authentication process.
     * 
     * @param principals A set of principals.
     * @param credentials A set of credentials.
     * @return an AuthenticationToken if the subject was authenticated, null otherwise.
     */
    AuthenticationToken authenticate(AuthenticationSubject subject);

}
