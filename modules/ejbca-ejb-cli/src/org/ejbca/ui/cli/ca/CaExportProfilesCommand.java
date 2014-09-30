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

import java.beans.XMLEncoder;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.Collection;

import org.apache.log4j.Logger;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Export profiles from the database to XML-files.
 *
 * @version $Id$
 */
public class CaExportProfilesCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaExportProfilesCommand.class);

    private static final String DIRECTORY_KEY = "-d";

    {
        registerParameter(new Parameter(DIRECTORY_KEY, "Directory name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The destination directory."));
    }

    @Override
    public String getMainCommand() {
        return "exportprofiles";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String outpath = parameters.get(DIRECTORY_KEY);
        if (!new File(outpath).isDirectory()) {
            log.error("Error: '" + outpath + "' is not a directory.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        Collection<Integer> certprofids = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getAuthorizedCertificateProfileIds(getAuthenticationToken(), 0);
        Collection<Integer> endentityprofids = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                .getAuthorizedEndEntityProfileIds(getAuthenticationToken());

        log.info("Exporting non-fixed certificate profiles: ");
        try {
            for (int profileid : certprofids) {
                if (profileid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) { // Certificate profile not found i database.
                    log.error("Couldn't find certificate profile '" + profileid + "' in database.");
                } else if (CertificateProfileConstants.isFixedCertificateProfile(profileid)) {
                    //log.debug("Skipping export fixed certificate profile with id '"+profileid+"'.");
                } else {
                    String profilename = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(
                            profileid);
                    CertificateProfile profile = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                            .getCertificateProfile(profileid);
                    if (profile == null) {
                        log.error("Couldn't find certificate profile '" + profilename + "'-" + profileid + " in database.");
                    } else {
                        String profilenameEncoded;
                        try {
                            profilenameEncoded = URLEncoder.encode(profilename, "UTF-8");
                        } catch (UnsupportedEncodingException e) {
                            throw new IllegalStateException("UTF-8 was not a known encoding", e);
                        }
                        final String outfile = outpath + "/certprofile_" + profilenameEncoded + "-" + profileid + ".xml";
                        log.info(outfile + ".");
                        XMLEncoder encoder = new XMLEncoder(new FileOutputStream(outfile));
                        encoder.writeObject(profile.saveData());
                        encoder.close();
                    }
                }
            }
            log.info("Exporting non-fixed end entity profiles: ");

            for (int profileid : endentityprofids) {
                if (profileid == SecConst.PROFILE_NO_PROFILE) { // Entity profile not found i database.
                    log.error("Error : Couldn't find entity profile '" + profileid + "' in database.");
                } else if (profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                    //log.debug("Skipping export fixed end entity profile with id '"+profileid+"'.");
                } else {
                    String profilename = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(
                            profileid);
                    EndEntityProfile profile = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfile(
                            profileid);
                    if (profile == null) {
                        log.error("Error : Couldn't find entity profile '" + profilename + "'-" + profileid + " in database.");
                    } else {
                        String profilenameEncoded;
                        try {
                            profilenameEncoded = URLEncoder.encode(profilename, "UTF-8");
                        } catch (UnsupportedEncodingException e) {
                            throw new IllegalStateException("UTF-8 was not a known encoding", e);
                        }
                        final String outfile = outpath + "/entityprofile_" + profilenameEncoded + "-" + profileid + ".xml";
                        log.info(outfile + ".");
                        XMLEncoder encoder = new XMLEncoder(new FileOutputStream(outfile));
                        encoder.writeObject(profile.saveData());
                        encoder.close();
                    }
                }
            }
        } catch (FileNotFoundException e) {
            log.error("Could not create export files", e);
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        return CommandResult.SUCCESS;

    }

    @Override
    public String getCommandDescription() {
        return "Export profiles from the database to XML-files.";

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
