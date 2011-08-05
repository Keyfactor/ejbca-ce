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

import org.cesecore.authentication.tokens.AuthenticationProvider;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;

/**
 * An identified subject needs to be authenticated in order to perform access control decisions.
 * 
 * In order to avoid sending EJBs or EntityManagers to POJOs as parameters, the {@code authenticate(...)} method takes an
 * {@link AuthenticationProvider AuthenticationProvider} as an argument. This interface should point to an EJB outside of CESeCore which handles the
 * nitty gritty job of authentication. Users may be tempted to avoid using this bean at all, and may do so if they wish, but they will have to
 * manually implement the auditing functions.
 * 
 * See {@link https://www.cesecore.eu/mediawiki/index.php/Functional_Specifications_(ADV_FSP)#Authentication}
 * 
 * Based on cesecore version:
 *      AuthenticationSession.java 168 2011-01-27 10:07:30Z mikek
 * 
 * @version $Id$
 * 
 */
public interface AuthenticationSession {

    /**
     * Retrieves an AuthenticationToken from the provided AuthenticationProvider, based on the provided Subject.
     * 
     * @param subject A Subject to evaluate.
     * @param authenticationProvider An interface to the class which perform the authentication.
     * @return An AuthenticationToken derived from the Subject, or null if authentication fails.
     */
    AuthenticationToken authenticate(final AuthenticationSubject subject, AuthenticationProvider authenticationProvider);

}
