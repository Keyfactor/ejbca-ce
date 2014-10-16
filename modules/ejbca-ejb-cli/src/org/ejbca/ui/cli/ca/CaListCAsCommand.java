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

package org.ejbca.ui.cli.ca;

import java.security.cert.Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Lists the names of all available CAs.
 *
 * @version $Id$
 */
public class CaListCAsCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaListCAsCommand.class);

    @Override
    public String getMainCommand() {
        return "listcas";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        CryptoProviderTools.installBCProvider();
        Collection<Integer> caids = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaIds(getAuthenticationToken());
        try {
            for (int caid : caids) {
                CAInfo ca;
                try {
                    ca = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caid);
                } catch (CADoesntExistsException e) {
                    throw new IllegalStateException("Newly retrieved CA not found.", e);
                }
                Collection<Certificate> certs = ca.getCertificateChain();
                Iterator<Certificate> ci = certs.iterator();
                Certificate cacert = null;
                if (ci.hasNext()) {
                    cacert = (Certificate) ci.next();
                }
                getLogger().info("CA Name: " + ca.getName());
                getLogger().info(" Id: " + ca.getCAId());
                if (cacert != null) {
                    getLogger().info(" Issuer DN: " + CertTools.getIssuerDN(cacert));
                }
                getLogger().info(" Subject DN: " + ca.getSubjectDN());
                getLogger().info(" Type: " + ca.getCAType());
                getLogger().info(" Expire time: " + ca.getExpireTime());
                getLogger().info(" Signed by: " + ca.getSignedBy());
            }
            return CommandResult.SUCCESS;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to view CAs");
            return CommandResult.AUTHORIZATION_FAILURE;
        }

    }

    @Override
    public String getCommandDescription() {
        return "Lists the names of all available CAs";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
