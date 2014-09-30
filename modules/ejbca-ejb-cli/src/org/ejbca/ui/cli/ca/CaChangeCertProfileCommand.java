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
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Changes the certificate profile of a CA.
 *
 * @version $Id$
 */
public class CaChangeCertProfileCommand extends BaseCaAdminCommand {

    private static final String CA_NAME_KEY = "--caname";
    private static final String CERTIFICATE_PROFILE_NAME = "--certprofile";

    private static final Logger log = Logger.getLogger(CaChangeCertProfileCommand.class);

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of the CA."));
        registerParameter(new Parameter(CERTIFICATE_PROFILE_NAME, "Certificate Progile Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT, "The name of the certificate profile"));
    }

    @Override
    public String getMainCommand() {
        return "changecertprofile";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");
        CryptoProviderTools.installBCProvider(); // need this for CVC certificate

        try {
            final String caName = parameters.get(CA_NAME_KEY);
            {
                final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
                final String certProfileName = parameters.get(CERTIFICATE_PROFILE_NAME);
                log.debug("Searching for Certificate Profile " + certProfileName);
                final int certificateprofileid = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                        .getCertificateProfileId(certProfileName);
                if (certificateprofileid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                    log.error("Certificate Profile " + certProfileName + " does not exist.");
                    throw new Exception("Certificate Profile '" + certProfileName + "' does not exist.");
                }
                cainfo.setCertificateProfileId(certificateprofileid);
                EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).editCA(getAuthenticationToken(), cainfo);
            }
            {
                final CAInfo cainfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
                log.info("Certificate profile for CA changed:");
                log.info("CA Name: " + caName);
                log.info("Certificate Profile: "
                        + EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(
                                cainfo.getCertificateProfileId()));
            }
        } catch (Exception e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        log.trace("<execute()");
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Changes the certificate profile of a CA.";
    }

    @Override
    public String getFullHelpText() {
        StringBuffer sb = new StringBuffer();
        sb.append(getCommandDescription() + "\n\n");
        sb.append(getCaList());
        // Print available Root CA and Sub CA profiles
        Collection<Integer> cpssub = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getAuthorizedCertificateProfileIds(getAuthenticationToken(), CertificateConstants.CERTTYPE_SUBCA);
        Collection<Integer> cpsroot = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getAuthorizedCertificateProfileIds(getAuthenticationToken(), CertificateConstants.CERTTYPE_ROOTCA);
        sb.append("Root CA profiles:\n");
        StringBuilder rootCaProfiles = new StringBuilder();
        for (Integer id : cpsroot) {
            rootCaProfiles.append("   "
                    + EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(id) + "\n");
        }
        sb.append(rootCaProfiles);
        sb.append("Sub CA profiles:\n");
        StringBuilder subCaProfiles = new StringBuilder();
        for (Integer id : cpssub) {
            subCaProfiles.append("   "
                    + EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(id) + "\n");
        }
        subCaProfiles.append("\n");
        sb.append(subCaProfiles);
        return sb.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
}
