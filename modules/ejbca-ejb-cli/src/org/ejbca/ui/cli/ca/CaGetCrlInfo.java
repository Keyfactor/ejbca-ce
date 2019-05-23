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

import org.apache.commons.lang.math.IntRange;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
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

        final Collection<Integer> caIds = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaIds(getAuthenticationToken());
        for (Integer caId : caIds) {
            CAInfo caInfo;
            try {
                caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caId);
            } catch (AuthorizationDeniedException e) {
                throw new IllegalStateException("CLI user was not authorized to retrieved CA.", e);
            } 
            final StringBuilder stringBuilder = new StringBuilder();
            final IntRange allCrlPartitionIndexes = caInfo.getAllCrlPartitionIndexes();
            final CrlStoreSessionRemote crlStoreSessionRemote = EjbRemoteHelper.INSTANCE.getRemoteSession(CrlStoreSessionRemote.class);
            if(allCrlPartitionIndexes == null) {
                outputCrlHeader(stringBuilder, caInfo);
                final CRLInfo crlInfo = crlStoreSessionRemote.getLastCRLInfo(caInfo.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, false);
                outputCrlInfo(stringBuilder, crlInfo, null,false);
                final CRLInfo deltaCrlInfo = crlStoreSessionRemote.getLastCRLInfo(caInfo.getSubjectDN(), CertificateConstants.NO_CRL_PARTITION, true);
                outputCrlInfo(stringBuilder, deltaCrlInfo, null,true);
            }
            else {
                for (int crlPartitionIndex = allCrlPartitionIndexes.getMinimumInteger(); crlPartitionIndex <= allCrlPartitionIndexes.getMaximumInteger(); crlPartitionIndex++) {
                    outputCrlHeader(stringBuilder, caInfo);
                    final CRLInfo crlInfo = crlStoreSessionRemote.getLastCRLInfo(caInfo.getSubjectDN(), crlPartitionIndex, false);
                    outputCrlInfo(stringBuilder, crlInfo, crlPartitionIndex, false);
                    final CRLInfo deltaCrlInfo = crlStoreSessionRemote.getLastCRLInfo(caInfo.getSubjectDN(), crlPartitionIndex, true);
                    outputCrlInfo(stringBuilder, deltaCrlInfo, crlPartitionIndex,true);
                    if(crlPartitionIndex < allCrlPartitionIndexes.getMaximumInteger()) {
                        stringBuilder.append(System.getProperty("line.separator"));
                    }
                }
            }
            log.info(stringBuilder.toString());
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

    private void outputCrlHeader(final StringBuilder stringBuilder, final CAInfo caInfo) {
        stringBuilder.append("\"").append(caInfo.getName()).append("\" \"").append(caInfo.getSubjectDN()).append("\"");
    }

    private void outputCrlInfo(final StringBuilder stringBuilder, final CRLInfo crlInfo, final Integer crlPartitionIndex, final boolean isDeltaCrl) {
        if (crlInfo != null) {
            stringBuilder.append( ( isDeltaCrl ? " DELTACRL# " : " CRL# ") ).append(crlInfo.getLastCRLNumber()).append( (crlPartitionIndex == null ? "" : " Partition# " + crlPartitionIndex) );
            stringBuilder.append(" issued ").append(ValidityDate.formatAsUTC(crlInfo.getCreateDate()));
            stringBuilder.append(" expires ").append(ValidityDate.formatAsUTC(crlInfo.getExpireDate()));
        } else {
            stringBuilder.append( ( isDeltaCrl ? " NO_DELTACRL_ISSUED" : " NO_CRL_ISSUED" ) );
        }
    }
}
