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
package org.ejbca.ui.cli.keybind;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.keybind.InternalKeyBinding;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingTrustEntry;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.keys.token.CryptoTokenInfo;
import org.cesecore.keys.token.CryptoTokenManagementSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.ui.DynamicUiProperty;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;

/**
 * Implements the CLI command <code>./ejbca.sh keybind list</code>.
 * 
 * @version $Id$
 */
public class InternalKeyBindingListCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(InternalKeyBindingListCommand.class);

    @Override
    public String[] getCommandPath() {
        return new String[] { "keybind" };
    }

    @Override
    public String getMainCommand() {
        return "list";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        final CryptoTokenManagementSessionRemote cryptoTokenManagementSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(CryptoTokenManagementSessionRemote.class);
        final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        final CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        final List<InternalKeyBindingInfo> internalKeyBindings = internalKeyBindingMgmtSession.getInternalKeyBindingInfos(
                getAuthenticationToken(), null);
        // Sort by type and name
        Collections.sort(internalKeyBindings, new Comparator<InternalKeyBinding>() {
            @Override
            public int compare(InternalKeyBinding o1, InternalKeyBinding o2) {
                final int typeCompare = o1.getImplementationAlias().compareTo(o2.getImplementationAlias());
                if (typeCompare != 0) {
                    return typeCompare;
                }
                return o1.getName().compareTo(o2.getName());
            }
        });
        if (internalKeyBindings.size() == 0) {
            getLogger().info(" No InternalKeyBindings available or you are not authorized to view any.");
        } else {
            getLogger()
                    .info(" Type\t\"Name\" (id), Status, \"IssuerDN\", SerialNumber, \"CryptoTokenName\" (id), "
                            + "KeyPairAlias, NextKeyPairAlias, SignatureAlgorithm, "
                            + "properties={Implementations specific properties}, "
                            + "trust={list of trusted CAs and certificates}, "
                            + "signOcspResponsesOnBehalf={list of other CAs for which responses are signed}");
        }
        final Date now = new Date();
        for (final InternalKeyBindingInfo internalKeyBinding : internalKeyBindings) {
            final StringBuilder sb = new StringBuilder();
            final int cryptoTokenId = internalKeyBinding.getCryptoTokenId();
            try {
                sb.append(' ').append(internalKeyBinding.getImplementationAlias());
                sb.append('\t').append('\"').append(internalKeyBinding.getName()).append('\"');
                sb.append(" (").append(internalKeyBinding.getId()).append(')');
                final CertificateInfo certificateInfo = certificateStoreSession.getCertificateInfo(internalKeyBinding.getCertificateId());
                String status = internalKeyBinding.getStatus().name();
                String issuerDn = "n/a,";
                String serialNumber = "n/a";
                if (certificateInfo != null) {
                    // We don't check for "Not yet valid" status to avoid another remote EJB call and this should be a rare thing.
                    if (certificateInfo.getExpireDate().before(now)) {
                        status = "EXPIRED";
                    } else if (certificateInfo.getStatus() == CertificateConstants.CERT_REVOKED) {
                        status = "REVOKED";
                    }
                    issuerDn = "\"" + certificateInfo.getIssuerDN() + "\",";
                    serialNumber = certificateInfo.getSerialNumber().toString(16).toUpperCase();
                }
                sb.append(", ").append(status);
                sb.append(", ").append(issuerDn).append(" ").append(serialNumber);

                final CryptoTokenInfo cryptoTokenInfo = cryptoTokenManagementSession.getCryptoTokenInfo(getAuthenticationToken(), cryptoTokenId);
                final String cryptoTokenName;
                if (cryptoTokenInfo == null) {                        
                    cryptoTokenName = "(CryptoToken does not exist)";
                } else {
                    cryptoTokenName = cryptoTokenInfo.getName();
                }
                sb.append(", \"").append(cryptoTokenName).append("\" (").append(cryptoTokenId).append(')');
                sb.append(", ").append(internalKeyBinding.getKeyPairAlias());
                sb.append(", ").append(internalKeyBinding.getNextKeyPairAlias());
                sb.append(", ").append(internalKeyBinding.getSignatureAlgorithm());
                sb.append(", properties={");
                final Collection<DynamicUiProperty<? extends Serializable>> properties = internalKeyBinding.getCopyOfProperties()
                        .values();
                for (final DynamicUiProperty<? extends Serializable> property : properties) {
                    sb.append("\n\t").append(property.getName()).append('=').append(property.getValue());
                    sb.append(" [").append(property.getType().getSimpleName()).append(", default=").append(property.getDefaultValue()).append("],");
                }
                if (properties.size() > 0) {
                    sb.deleteCharAt(sb.length() - 1);
                }
                sb.append("\n }, \ttrust={");
                final List<InternalKeyBindingTrustEntry> internalKeyBindingTrustEntries = internalKeyBinding.getTrustedCertificateReferences();
                if (internalKeyBindingTrustEntries.isEmpty()) {
                    sb.append("\n\t\tANY certificate issued by a known CA");
                } else {
                    for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : internalKeyBindingTrustEntries) {
                        final String caSubject = caSession.getCAInfo(getAuthenticationToken(), internalKeyBindingTrustEntry.getCaId())
                                .getSubjectDN();
                        sb.append("\n\t\"").append(caSubject).append("\", ");
                        if (internalKeyBindingTrustEntry.fetchCertificateSerialNumber() == null) {
                            sb.append("ANY certificate");
                        } else {
                            sb.append(internalKeyBindingTrustEntry.fetchCertificateSerialNumber().toString(16));
                        }
                    }
                }
                if(internalKeyBinding.getImplementationAlias().equals(OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
                    sb.append("\n }, \tsignOnBehalfOfCas={");
                    final List<InternalKeyBindingTrustEntry> internalKeyBindingSignOnBehalfEntries = internalKeyBinding.getSignOcspResponseOnBehalf();
                    if (internalKeyBindingSignOnBehalfEntries.isEmpty()) {
                        sb.append("\n\t\tOnly certificates issued by a current CA");
                    } else {
                        for (final InternalKeyBindingTrustEntry internalKeyBindingTrustEntry : internalKeyBindingSignOnBehalfEntries) {
                            final String caSubject = caSession.getCAInfo(getAuthenticationToken(), internalKeyBindingTrustEntry.getCaId())
                                    .getSubjectDN();
                            sb.append("\n\t\t\"").append(caSubject).append("\", ");
                        }
                    }
                }
                sb.append("\n }");
                if (OcspKeyBinding.IMPLEMENTATION_ALIAS.equals(internalKeyBinding.getImplementationAlias())) {
                    sb.append(", ocspExtensions={");
                    for (final String ocspExtension : internalKeyBinding.getOcspExtensions()) {
                        sb.append(System.lineSeparator() + "\tOID: " + ocspExtension);
                    }
                    if (internalKeyBinding.getOcspExtensions().contains(OCSPObjectIdentifiers.id_pkix_ocsp_archive_cutoff.getId())) {
                        sb.append(System.lineSeparator() + " }, archiveCutoff={" + System.lineSeparator());
                        if (internalKeyBinding.useIssuerNotBeforeAsArchiveCutoff()) {
                            sb.append("\tUsing issuer's noBefore date as archive cutoff date (ETSI EN 319 411-2, CSS-6.3.10-08)."
                                    + System.lineSeparator());
                        } else {
                            sb.append(
                                    "\tUsing a retention period of '" + internalKeyBinding.getRetentionPeriod().toString() + "'."
                                            + System.lineSeparator());
                        }
                    }
                    sb.append(" }");
                }
                getLogger().info(sb);
            } catch (AuthorizationDeniedException e) {
                log.error("CLI user not authorized to view key bindings.");
                return CommandResult.AUTHORIZATION_FAILURE;
            }
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "List all available InternalKeyBindings";
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
