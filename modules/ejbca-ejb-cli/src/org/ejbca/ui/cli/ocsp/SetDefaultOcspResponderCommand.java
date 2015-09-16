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
package org.ejbca.ui.cli.ocsp;

import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAConstants;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.config.GlobalOcspConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.keybind.InternalKeyBindingInfo;
import org.cesecore.keybind.InternalKeyBindingMgmtSessionRemote;
import org.cesecore.keybind.InternalKeyBindingStatus;
import org.cesecore.keybind.impl.OcspKeyBinding;
import org.cesecore.util.CertTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * See getDescription().
 * 
 * @version $Id$
 */
public class SetDefaultOcspResponderCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(SetDefaultOcspResponderCommand.class);

    private static final String DN_KEY = "--dn";

    {
        registerParameter(new Parameter(DN_KEY, "DN", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "DN to set as default responder."));
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "ocsp" };
    }

    @Override
    public String getMainCommand() {
        return "setdefaultresponder";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(GlobalConfigurationSessionRemote.class);
        GlobalOcspConfiguration conf = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        String reference = parameters.get(DN_KEY);
        conf.setOcspDefaultResponderReference(reference);
        try {
            globalConfigurationSession.saveConfiguration(getAuthenticationToken(), conf);
            log.info("Setting '" + reference + "' as the default responder.");
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: Current CLI user wasn't authorized to edit configuration.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Sets the default OCSP responder.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(getCommandDescription());
        stringBuilder
                .append(" The value is saved in the form of a DN, either the subject DN of the CA or the issuer DN of the Internal Keybinding chosen as default responder.");
        stringBuilder
                .append(" Note that input from this command is not vetted, so be sure to be exact in setting the value. DNs inputed in reverse order will be saved in standard order.");
        stringBuilder.append(" If no default responder is to be set, simply enter an emptry string within quotes (\"\"). Local CAs with active OCSP Keybindings will not be listed.\n\n");
        InternalKeyBindingMgmtSessionRemote internalKeyBindingMgmtSession = EjbRemoteHelper.INSTANCE.getRemoteSession(InternalKeyBindingMgmtSessionRemote.class);
        CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
        List<String[]> ikbContents = new ArrayList<String[]>();
        Set<String> knownDNs = new HashSet<String>();
        for(InternalKeyBindingInfo info : internalKeyBindingMgmtSession.getInternalKeyBindingInfos(getAuthenticationToken(), OcspKeyBinding.IMPLEMENTATION_ALIAS)) {
            if(info.getStatus().equals(InternalKeyBindingStatus.ACTIVE)) {
                Certificate certificate = EJBTools.unwrap(certificateStoreSession.findCertificateByFingerprintRemote(info.getCertificateId()));
                ikbContents.add(new String[]{info.getName(), CertTools.getIssuerDN(certificate)});
                knownDNs.add(CertTools.getIssuerDN(certificate));
            }
        }
        if(!ikbContents.isEmpty()) {
            stringBuilder.append(bold("The following Internal Keybindings are available as signers:\n"));
            stringBuilder.append(formatTable(1, new String[] { "Keybinding Name:", "Issuer DN:" }, ikbContents));
            stringBuilder.append("\n");
        }
        CaSessionRemote caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        List<String[]> caContents = new ArrayList<String[]>();     
        for (CAInfo caInfo : caSession.getAuthorizedAndEnabledCaInfos(getAuthenticationToken())) {
            final String caSubjectDn = CertTools.getSubjectDN(new ArrayList<Certificate>(caInfo.getCertificateChain()).get(0));
            if (caInfo.getCAType() == CAInfo.CATYPE_X509 && !knownDNs.contains(caSubjectDn) && caInfo.getStatus() == CAConstants.CA_ACTIVE) {
                caContents.add(new String[] { caInfo.getName(), caSubjectDn});
            }
        }
        if (!caContents.isEmpty()) {
            stringBuilder.append(bold("The following CAs are available as signers:\n"));
            stringBuilder.append(formatTable(1, new String[] { "CA Name:", "Subject DN:" }, caContents));
            stringBuilder.append("\n");
        }
       
        GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE
                .getRemoteSession(GlobalConfigurationSessionRemote.class);
        GlobalOcspConfiguration conf = (GlobalOcspConfiguration) globalConfigurationSession
                .getCachedConfiguration(GlobalOcspConfiguration.OCSP_CONFIGURATION_ID);
        stringBuilder.append("The current default responder is: " + conf.getOcspDefaultResponderReference());
        return stringBuilder.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
