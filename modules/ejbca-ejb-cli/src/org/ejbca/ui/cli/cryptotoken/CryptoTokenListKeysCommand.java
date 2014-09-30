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
package org.ejbca.ui.cli.cryptotoken;

import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyPairInfo;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * CryptoToken EJB CLI command. See {@link #getDescription()} implementation.
 * 
 * @version $Id$
 */
public class CryptoTokenListKeysCommand extends BaseCryptoTokenCommand {

    private static final Logger log = Logger.getLogger(CryptoTokenListKeysCommand.class);

    @Override
    public String getMainCommand() {
        return "listkeys";
    }

    @Override
    public CommandResult executeCommand(Integer cryptoTokenId, ParameterContainer parameters) throws AuthorizationDeniedException, CryptoTokenOfflineException {
        final String cryptoTokenName = parameters.get(CRYPTOTOKEN_NAME_KEY);
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final List<KeyPairInfo> keyPairInfos = cryptoTokenManagementSession.getKeyPairInfos(getAdmin(), cryptoTokenId);
        getLogger().info("CryptoToken name: \"" + cryptoTokenName + "\"");
        getLogger().info("CryptoToken id:   " + cryptoTokenId + "\n");
        getLogger().info(" ALIAS\t ALGORITHM SPECIFICATION SUBJECTKEYID");
        for (final KeyPairInfo keyPairInfo : keyPairInfos) {
            final StringBuilder sb = new StringBuilder();
            sb.append(' ').append(keyPairInfo.getAlias());
            sb.append('\t').append(keyPairInfo.getKeyAlgorithm());
            sb.append(' ').append(keyPairInfo.getKeySpecification());
            sb.append(' ').append(keyPairInfo.getSubjectKeyID());
            getLogger().info(sb);
        }
        if (keyPairInfos.isEmpty()) {
            getLogger().info("CryptoToken does not contain any key pairs.");
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "List all key pairs in an active token";
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
