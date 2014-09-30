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

import java.beans.XMLDecoder;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;

import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.publisher.PublisherSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ca.publisher.BasePublisher;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileExistsException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Import profiles from XML-files to the database.
 *
 * @version $Id$
 */
public class CaImportProfilesCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportProfilesCommand.class);

    private static final String DIRECTORY_KEY = "-d";
    private static final String CA_NAME_KEY = "--caname";

    {
        registerParameter(new Parameter(DIRECTORY_KEY, "Directory", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Directory containing profiles."));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of a CA to restrict imported profiles to."));
    }

    @Override
    public String getMainCommand() {
        return "importprofiles";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        String inpath = parameters.get(DIRECTORY_KEY);
        Integer caid = null;
        String caName = parameters.get(CA_NAME_KEY);
        if (caName != null) {
            CAInfo ca;
            try {
                ca = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caName);
            } catch (CADoesntExistsException e) {
                getLogger().error("CA '" + caName + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            } catch (AuthorizationDeniedException e) {
                getLogger().error("CLI user not authorized to CA '" + caName);
                return CommandResult.AUTHORIZATION_FAILURE;
            }
            if (ca != null) {
                caid = ca.getCAId();
            } else {
                getLogger().error("CA '" + caName + "' does not exist.");
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        CryptoProviderTools.installBCProvider();
        // Mapping used to translate certificate profile ids when importing end entity profiles. Used when the profile id of a cert profile changes
        // and we need to change the mapping from the ee profile to cert profiles
        HashMap<Integer, Integer> certificateProfileIdMapping = new HashMap<Integer, Integer>();
        getLogger().info("Importing certificate and end entity profiles: ");
        File inFile = new File(inpath);
        if (!inFile.isDirectory()) {
            getLogger().error("'" + inpath + "' is not a directory.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        // List all filenames in the given directory, we will try to import them all
        File[] infiles = inFile.listFiles();
        FileTools.sortByName(infiles);
        try {
            for (int i = 0; i < infiles.length; i++) {
                getLogger().info("Filename: " + infiles[i].getName());
                if (infiles[i].isFile()
                        && ((infiles[i].getName().indexOf("certprofile_") > -1) || (infiles[i].getName().indexOf("entityprofile_") > -1))) {
                    boolean entityprofile = false;
                    if (infiles[i].getName().indexOf("entityprofile_") > -1) {
                        entityprofile = true;
                    }
                    int index1 = infiles[i].getName().indexOf("_");
                    int index2 = infiles[i].getName().lastIndexOf("-");
                    int index3 = infiles[i].getName().lastIndexOf(".xml");
                    if (index1 < 0 || index2 < 0 || index3 < 0) {
                        getLogger().error("Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
                    } else {
                        final String filename = infiles[i].getName().substring(index1 + 1, index2);
                        String profilename;
                        try {
                            profilename = URLDecoder.decode(filename, "UTF-8");
                        } catch (UnsupportedEncodingException e) {
                            throw new IllegalStateException("UTF-8 was not a known character encoding", e);
                        }
                        int profileid = Integer.parseInt(infiles[i].getName().substring(index2 + 1, index3));
                        // We don't add the fixed profiles, EJBCA handles those automagically
                        if (!entityprofile && CertificateProfileConstants.isFixedCertificateProfile(profileid)) {
                            getLogger().error("Not adding fixed certificate profile '" + profilename + "'.");
                        } else {
                            if (entityprofile && profileid == SecConst.EMPTY_ENDENTITYPROFILE) {
                                getLogger().error("Not adding fixed entity profile '" + profilename + "'.");
                            } else {
                                // Check if the profiles already exist, and change the name and id if already taken
                                boolean error = false;
                                // when we need to create a new certprofile id, this will hodl the original value so we
                                // can insert a mapping in certificateProfileIdMapping when we have created a new id
                                int oldprofileid = -1;
                                if (entityprofile) {
                                    if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfile(
                                            profilename) != null) {
                                        getLogger().error("Entity profile '" + profilename + "' already exist in database.");
                                        error = true;
                                    } else if (EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfile(
                                            profileid) != null) {
                                        int newprofileid = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                                                .findFreeEndEntityProfileId();
                                        getLogger()
                                                .warn("Entity profileid '" + profileid + "' already exist in database. Using " + newprofileid
                                                        + " instead.");
                                        profileid = newprofileid;
                                    }
                                } else {
                                    if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(
                                            profilename) != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                                        getLogger().error("Error: Certificate profile '" + profilename + "' already exist in database.");
                                        error = true;
                                    } else if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                            .getCertificateProfile(profileid) != null) {
                                        getLogger().warn(
                                                "Certificate profile id '" + profileid
                                                        + "' already exist in database. Adding with a new profile id instead.");
                                        oldprofileid = profileid;
                                        profileid = -1; // means we should create a new id when adding the cert profile
                                    }
                                }
                                if (!error) {
                                    CertificateProfile cprofile = null;
                                    EndEntityProfile eprofile = null;
                                    FileInputStream is;
                                    try {
                                        is = new FileInputStream(infiles[i]);
                                    } catch (FileNotFoundException e) {
                                        //Shouldn't happen, we've already vetted the file directory above
                                        throw new IllegalStateException("An exception was encountered with an already vetted file directory", e);
                                    }
                                    XMLDecoder decoder = new XMLDecoder(is);
                                    if (entityprofile) {
                                        // Add end entity profile
                                        eprofile = new EndEntityProfile();
                                        eprofile.loadData(decoder.readObject());
                                        // Translate cert profile ids that have changed after import
                                        String availableCertProfiles = "";
                                        String defaultCertProfile = eprofile.getValue(EndEntityProfile.DEFAULTCERTPROFILE, 0);
                                        //getLogger().debug("Debug: Org - AVAILCERTPROFILES " + eprofile.getValue(EndEntityProfile.AVAILCERTPROFILES,0) + " DEFAULTCERTPROFILE "+defaultCertProfile);
                                        for (String currentCertProfile : (Collection<String>) eprofile.getAvailableCertificateProfileIds()) {
                                            Integer currentCertProfileId = Integer.parseInt(currentCertProfile);
                                            Integer replacementCertProfileId = certificateProfileIdMapping.get(currentCertProfileId);
                                            if (replacementCertProfileId != null) {
                                                if (!replacementCertProfileId.toString().equals(currentCertProfile)) {
                                                    getLogger().warn(
                                                            "Replacing cert profile with id " + currentCertProfile + " with "
                                                                    + replacementCertProfileId + ".");
                                                }
                                                availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";") + replacementCertProfileId;
                                                if (currentCertProfile.equals(defaultCertProfile)) {
                                                    defaultCertProfile = "" + replacementCertProfileId;
                                                }
                                            } else {
                                                if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                                        .getCertificateProfile(currentCertProfileId) != null
                                                        || CertificateProfileConstants.isFixedCertificateProfile(currentCertProfileId)) {
                                                    availableCertProfiles += (availableCertProfiles.equals("") ? "" : ";") + currentCertProfile;
                                                } else {
                                                    getLogger().warn(
                                                            "End Entity Profile '" + profilename + "' references certificate profile "
                                                                    + currentCertProfile + " that does not exist.");
                                                    if (currentCertProfile.equals(defaultCertProfile)) {
                                                        defaultCertProfile = "";
                                                    }
                                                }
                                            }
                                        }
                                        if (availableCertProfiles.equals("")) {
                                            getLogger()
                                                    .warn("End Entity Profile only references certificate profile(s) that does not exist. Using ENDUSER profile.");
                                            availableCertProfiles = "1"; // At least make sure the default profile is available
                                        }
                                        if (defaultCertProfile.equals("")) {
                                            defaultCertProfile = availableCertProfiles.split(";")[0]; // Use first available profile from list as default if original default was missing
                                        }
                                        eprofile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, availableCertProfiles);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, defaultCertProfile);
                                        // Remove any unknown CA and break if none is left
                                        String defaultCA = eprofile.getValue(EndEntityProfile.DEFAULTCA, 0);
                                        String availableCAs = eprofile.getValue(EndEntityProfile.AVAILCAS, 0);
                                        //getOutputStream().println("Debug: Org - AVAILCAS " + availableCAs + " DEFAULTCA "+defaultCA);
                                        List<String> cas = Arrays.asList(availableCAs.split(";"));
                                        availableCAs = "";
                                        for (String currentCA : cas) {
                                            Integer currentCAInt = Integer.parseInt(currentCA);
                                            // The constant ALLCAS will not be searched for among available CAs
                                            try {
                                                if (currentCAInt.intValue() != SecConst.ALLCAS) {
                                                    EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(
                                                            getAuthenticationToken(), currentCAInt);
                                                }
                                                availableCAs += (availableCAs.equals("") ? "" : ";") + currentCA; // No Exception means CA exists
                                            } catch (CADoesntExistsException e) {
                                                getLogger().warn(
                                                        "CA with id " + currentCA + " was not found and will not be used in end entity profile '"
                                                                + profilename + "'.");
                                                if (defaultCA.equals(currentCA)) {
                                                    defaultCA = "";
                                                }
                                            }
                                        }
                                        if (availableCAs.equals("")) {
                                            if (caid == null) {
                                                getLogger().error(
                                                        "No CAs left in end entity profile '" + profilename
                                                                + "' and no CA specified on command line. Using ALLCAs.");
                                                availableCAs = Integer.toString(SecConst.ALLCAS);
                                            } else {
                                                availableCAs = Integer.toString(caid);
                                                getLogger().warn(
                                                        "No CAs left in end entity profile '" + profilename
                                                                + "'. Using CA supplied on command line with id '" + caid + "'.");
                                            }
                                        }
                                        if (defaultCA.equals("")) {
                                            defaultCA = availableCAs.split(";")[0]; // Use first available
                                            getLogger().warn("Changing default CA in end entity profile '" + profilename + "' to " + defaultCA + ".");
                                        }
                                        //getLogger().debug("New - AVAILCAS " + availableCAs + " DEFAULTCA "+defaultCA);
                                        eprofile.setValue(EndEntityProfile.AVAILCAS, 0, availableCAs);
                                        eprofile.setValue(EndEntityProfile.DEFAULTCA, 0, defaultCA);
                                        try {
                                            EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).addEndEntityProfile(
                                                    getAuthenticationToken(), profileid, profilename, eprofile);
                                            getLogger().info("Added entity profile '" + profilename + "' to database.");
                                        } catch (EndEntityProfileExistsException eepee) {
                                            getLogger().error("Error adding entity profile '" + profilename + "' to database.");
                                        }
                                    } else {
                                        // Add certificate profile
                                        cprofile = new CertificateProfile();
                                        cprofile.loadData(decoder.readObject());
                                        // Make sure CAs in profile exist
                                        List<Integer> cas = cprofile.getAvailableCAs();
                                        ArrayList<Integer> casToRemove = new ArrayList<Integer>();
                                        for (Integer currentCA : cas) {
                                            // If the CA is not ANYCA and the CA does not exist, remove it from the profile before import
                                            if (currentCA != CertificateProfile.ANYCA) {
                                                try {
                                                    EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(
                                                            getAuthenticationToken(), currentCA);
                                                } catch (CADoesntExistsException e) {
                                                    casToRemove.add(currentCA);
                                                }
                                            }
                                        }
                                        for (Integer toRemove : casToRemove) {
                                            getLogger().warn(
                                                    "Warning: CA with id " + toRemove
                                                            + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                            cas.remove(toRemove);
                                        }
                                        if (cas.size() == 0) {
                                            if (caid == null) {
                                                getLogger().error(
                                                        "Error: No CAs left in certificate profile '" + profilename
                                                                + "' and no CA specified on command line. Using ANYCA.");
                                                cas.add(Integer.valueOf(CertificateProfile.ANYCA));
                                            } else {
                                                getLogger().warn(
                                                        "Warning: No CAs left in certificate profile '" + profilename
                                                                + "'. Using CA supplied on command line with id '" + caid + "'.");
                                                cas.add(caid);
                                            }
                                        }
                                        cprofile.setAvailableCAs(cas);
                                        // Remove and warn about unknown publishers
                                        List<Integer> publishers = cprofile.getPublisherList();
                                        ArrayList<Integer> allToRemove = new ArrayList<Integer>();
                                        for (Integer publisher : publishers) {
                                            BasePublisher pub = null;
                                            try {
                                                pub = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class).getPublisher(publisher);
                                            } catch (Exception e) {
                                                getLogger().warn(
                                                        "Warning: There was an error loading publisher with id " + publisher
                                                                + ". Use debug logging to see stack trace: " + e.getMessage());
                                                getLogger().debug("Full stack trace: ", e);
                                            }
                                            if (pub == null) {
                                                allToRemove.add(publisher);
                                            }
                                        }
                                        for (Integer toRemove : allToRemove) {
                                            getLogger().warn(
                                                    "Warning: Publisher with id " + toRemove
                                                            + " was not found and will not be used in certificate profile '" + profilename + "'.");
                                            publishers.remove(toRemove);
                                        }
                                        cprofile.setPublisherList(publishers);
                                        // Add profile
                                        try {
                                            if (profileid == -1) {
                                                // id already existed, we need to create a new one
                                                profileid = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                                        .addCertificateProfile(getAuthenticationToken(), profilename, cprofile);
                                                // make a mapping from the old id (that was already in use) to the new one so we can change end entity profiles
                                                certificateProfileIdMapping.put(oldprofileid, profileid);
                                            } else {
                                                EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                                        .addCertificateProfile(getAuthenticationToken(), profileid, profilename, cprofile);
                                            }
                                            // Make a mapping from the new to the new id, so we have a mapping if the profile id did not change at all
                                            certificateProfileIdMapping.put(profileid,
                                                    EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                                                            .getCertificateProfileId(profilename));
                                            getLogger().info("Added certificate profile '" + profilename + "', '" + profileid + "' to database.");
                                        } catch (CertificateProfileExistsException cpee) {
                                            getLogger().error(
                                                    "Error adding certificate profile '" + profilename + "', '" + profileid + "' to database.");
                                        }
                                    }
                                    decoder.close();
                                    try {
                                        is.close();
                                    } catch (IOException e) {
                                        throw new IllegalStateException("Unknown IOException was caught when closing stream", e);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } catch (AuthorizationDeniedException e) {
            log.error("Current CLI user doesn't have sufficient privileges to import profiles.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        return CommandResult.SUCCESS;
    }

    @Override
    public String getCommandDescription() {
        return "Import profiles from XML-files to the database";

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
