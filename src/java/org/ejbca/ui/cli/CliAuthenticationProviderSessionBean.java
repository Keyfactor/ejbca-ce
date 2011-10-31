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
package org.ejbca.ui.cli;

import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.Set;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;

import org.apache.log4j.Logger;
import org.cesecore.authentication.tokens.AuthenticationSubject;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authentication.tokens.UsernamePrincipal;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.util.Tuplet;
import org.ejbca.config.EjbcaConfiguration;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderLocal;
import org.ejbca.core.ejb.authentication.cli.CliAuthenticationProviderRemote;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionLocal;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionLocal;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.ui.cli.exception.CliAuthenticationFailedException;
import org.ejbca.util.crypto.BCrypt;
import org.ejbca.util.crypto.SupportedPasswordHashAlgorithm;

/**
 * This session bean provides authentication for CLI users. Notable features are that it interfaces against the
 * CliAuthenticationTokenReferenceRegistry to register tokens so that they are single use only, and in order to avoid sending passwords or password
 * hashes in cleartext over remote connections.
 * 
 * @version $Id$
 * 
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "CliAuthenticationProviderRemote")
@TransactionAttribute(TransactionAttributeType.SUPPORTS)
public class CliAuthenticationProviderSessionBean implements CliAuthenticationProviderLocal, CliAuthenticationProviderRemote {

    private static final long serialVersionUID = 3953734683130654792L;

    private static final Logger log = Logger.getLogger(CliAuthenticationProviderSessionBean.class);

    private volatile SecureRandom randomGenerator;

    @EJB
    private EndEntityAccessSessionLocal endEntityAccessSession;
    @EJB
    private GlobalConfigurationSessionLocal globalConfigurationSession;

    @PostConstruct
    public void initialize() throws RuntimeException {
        try {
            randomGenerator = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public AuthenticationToken authenticate(AuthenticationSubject subject) {
        /*
         * An extra check if CLI authentication is allowed. This must be done on the
         * server and not the client to avoid spoofing.
         */
        if (!globalConfigurationSession.getCachedGlobalConfiguration().getEnableCommandLineInterface()) {
            log.info("CLI authentication attempted, but CLI is disabled.");
            throw new CliAuthenticationFailedException("Could not authenticate from CLI, CLI is disabled.");
        } else {
            Set<Principal> subjectPrincipals = subject.getPrincipals();
            if (subjectPrincipals.size() == 0) {
                log.error("ClI Authentication was attempted without principals");
                return null;
            } else if (subjectPrincipals.size() > 1) {
                log.error("ClI Authentication was attempted with multiple principals");
                return null;
            }

            final long referenceId = randomGenerator.nextLong();

            UsernamePrincipal usernamePrincipal = subjectPrincipals.toArray((new UsernamePrincipal[subjectPrincipals.size()]))[0];
            
            if(!globalConfigurationSession.getCachedGlobalConfiguration().getEnableCommandLineInterfaceDefaultUser() 
                && usernamePrincipal.getName().equals(EjbcaConfiguration.getCliDefaultUser())) {
                log.info("CLI authentication attempted, but the default user ("+EjbcaConfiguration.getCliDefaultUser()+") is disabled.");
                throw new CliAuthenticationFailedException("Could not authenticate from CLI, use of default user is prohibited.");
            }

            try {
                Tuplet<String, SupportedPasswordHashAlgorithm> passwordAndAlgorithm = endEntityAccessSession
                        .getPasswordAndHashAlgorithmForUser(usernamePrincipal.getName());
                CliAuthenticationToken result = new CliAuthenticationToken(usernamePrincipal, passwordAndAlgorithm.getFirstElement(),
                        BCrypt.gensalt(EjbcaConfiguration.getPasswordLogRounds()), referenceId, passwordAndAlgorithm.getSecondElement());
                CliAuthenticationTokenReferenceRegistry.INSTANCE.registerToken(result);
                /*
                 * It is imperative that a cloned version of the
                 * CliAuthenticationToken is returned, not containing the SHA1
                 * hash.
                 */
                return result.clone();
            } catch (NotFoundException e) {
                log.error("User " + usernamePrincipal.getName() + " not found in database", e);
                return null;
            }
        }
    }

}
