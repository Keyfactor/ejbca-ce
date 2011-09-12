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
package org.ejbca.core.ejb.authentication.cli;

import java.security.Principal;
import java.util.Set;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.jndi.JndiConstants;

/**
 * 
 * @version $Id$
 *
 */

@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CliAuthenticationProviderRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CliAuthenticationProviderSessionBean implements CliAuthenticationProviderLocal, CliAuthenticationProviderRemote {

    private static final long serialVersionUID = 3953734683130654792L;

    private static final Logger log = Logger.getLogger(CliAuthenticationProviderSessionBean.class);
    
    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {
        // TODO Not implemented yet
        Set<Principal> subjectPrincipals = subject.getPrincipals();
        if(subjectPrincipals.size() == 0) {
            log.error("ClI Authentication was attempted without principals");
            return null;
        } else if (subjectPrincipals.size() > 1) {
            log.error("ClI Authentication was attempted with multiple principals");
            return null;
        }
        
        final long referenceId = 0;
        
        return new CliAuthenticationToken(subjectPrincipals.toArray((new UsernamePrincipal[subjectPrincipals.size()]))[0], referenceId);
    }

}
