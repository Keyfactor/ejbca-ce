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

import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.crl.CRLInfo;
import org.cesecore.certificates.crl.CrlStoreSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ValidityDate;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * List information about the latest CRL from each CA.
 *
 * @version $Id$
 */
public class CaGetCrlInfo extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaGetCrlInfo.class);

    @Override
    public String getMainCommand() {
        return "getcrlinfo";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        Collection<Integer> caIds = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCAs(getAuthenticationToken());
        for (Integer caId : caIds) {
            CAInfo cainfo;
            try {
                cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caId);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("CLI user was not authorized to retrieved CA.", e);
            } catch (CADoesntExistsException e) {
                throw new IllegalStateException("Previously retrieved CA does not exist", e);
            }
            final StringBuilder sb = new StringBuilder();
            sb.append("\"").append(cainfo.getName()).append("\" \"").append(cainfo.getSubjectDN()).append("\"");
            final CRLInfo crlInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLInfo(cainfo.getSubjectDN(),
                    false);
            if (crlInfo != null) {
                sb.append(" CRL# ").append(crlInfo.getLastCRLNumber());
                sb.append(" issued ").append(ValidityDate.formatAsUTC(crlInfo.getCreateDate()));
                sb.append(" expires ").append(ValidityDate.formatAsUTC(crlInfo.getExpireDate()));
            } else {
                sb.append(" NO_CRL_ISSUED");
            }
            final CRLInfo deltaCrlInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class).getLastCRLInfo(cainfo.getSubjectDN(),
                    true);
            if (deltaCrlInfo != null) {
                sb.append(" DELTACRL# ").append(deltaCrlInfo.getLastCRLNumber());
                sb.append(" issued ").append(ValidityDate.formatAsUTC(deltaCrlInfo.getCreateDate()));
                sb.append(" expires ").append(ValidityDate.formatAsUTC(deltaCrlInfo.getExpireDate()));
            } else {
                sb.append(" NO_DELTACRL_ISSUED");
            }
            log.info(sb.toString());
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "List information about latest CRLs";

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
