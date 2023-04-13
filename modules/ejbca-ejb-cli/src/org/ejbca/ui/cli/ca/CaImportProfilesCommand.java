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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificateprofile.CertificateProfile;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileExistsException;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SecureXMLDecoder;
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

import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.FileTools;

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

    private CaSessionRemote caSession = null;
    private CertificateProfileSessionRemote certificateProfileSession = null;
    private EndEntityProfileSessionRemote endEntityProfileSession = null;
    private PublisherSessionRemote publisherSession = null;

    @Override
    public String getMainCommand() {
        return "importprofiles";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        final String inputDir = parameters.get(DIRECTORY_KEY);
        if(inputDir == null) {
            getLogger().error("Directory parameter is mandatory.");
            return CommandResult.CLI_FAILURE;
        }
        final String caName = parameters.get(CA_NAME_KEY);
        Integer caId = null;
        if (caName != null) {
            CAInfo ca;
            try {
                ca = getCaSession().getCAInfo(getAuthenticationToken(), caName);
                if (ca == null) {
                    getLogger().error("CA '" + caName + "' does not exist.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            } catch (AuthorizationDeniedException e) {
                getLogger().error("CLI user not authorized to CA '" + caName + "'.");
                return CommandResult.AUTHORIZATION_FAILURE;
            }
            caId = ca.getCAId();
        }
        final File inputDirFile = new File(inputDir);
        if(!inputDirFile.canRead()) {
            getLogger().error("'" + inputDir + "' cannot be read.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        if (!inputDirFile.isDirectory()) {
            getLogger().error("'" + inputDir + "' is not a directory.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        // List all filenames in the given directory, we will try to import them all
        final File[] inputDirFiles = inputDirFile.listFiles();
        if(inputDirFiles == null || inputDirFiles.length == 0) {
            getLogger().error("'" + inputDir + "' is empty.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        //
        CryptoProviderTools.installBCProvider();
        // Mapping used to translate certificate profile ids when importing end entity profiles. Used when the profile id of a cert profile changes
        // and we need to change the mapping from the ee profile to cert profiles
        HashMap<Integer, Integer> certificateProfileIdMapping = new HashMap<>();
        getLogger().info("Importing certificate and end entity profiles: ");
        CommandResult commandResult = CommandResult.SUCCESS;
        FileTools.sortByName(inputDirFiles);
        try {
            for (File inputFile : inputDirFiles) {
                getLogger().info("Filename: '" + inputFile.getName() + "'");
                if (inputFile.isFile()) {
                    final String fileName = inputFile.getName();
                    ProfileInfo profileInfo = getProfileInfoFromFileName(fileName);
                    if(profileInfo == null) {
                        getLogger().info("Skipped: '" + fileName + "'");
                        commandResult = CommandResult.FUNCTIONAL_FAILURE;
                    }
                    else {
                        // We don't add the fixed profiles, EJBCA handles those automatically
                        if (profileInfo.isCertificateProfile && CertificateProfileConstants.isFixedCertificateProfile(profileInfo.getProfileId())) {
                            getLogger().error("Not adding fixed certificate profile '" + profileInfo.getProfileName() + "'.");
                        } else if (profileInfo.isEntityProfile() && profileInfo.getProfileId() == EndEntityConstants.EMPTY_END_ENTITY_PROFILE) {
                            getLogger().error("Not adding fixed entity profile '" + profileInfo.getProfileName() + "'.");
                        } else {
                            // Check if the profiles already exist, and change the name and id if already taken
                            profileInfo = checkIfProfileExists(profileInfo);
                            // when we need to create a new certprofile id, this will hold the original value so we
                            // can insert a mapping in certificateProfileIdMapping when we have created a new id
                            if (profileInfo.isOk()) {
                                final Object loadedObject;
                                try (SecureXMLDecoder decoder = new SecureXMLDecoder(new FileInputStream(inputFile))) {
                                    loadedObject = decoder.readObject();
                                } catch (FileNotFoundException e) {
                                    // Shouldn't happen, we've already vetted the file directory above
                                    throw new IllegalStateException("An exception was encountered with an already vetted file directory", e);
                                } catch (IOException e) {
                                    log.error("Failed to parse profile XML in '" + inputFile + "': " + e.getMessage());
                                    return CommandResult.FUNCTIONAL_FAILURE;
                                }
                                if (profileInfo.isEntityProfile) {
                                    // Add end entity profile
                                    EndEntityProfile endEntityProfile = new EndEntityProfile();
                                    endEntityProfile.loadData(loadedObject);
                                    // Translate cert profile ids that have changed after import
                                    final List<Integer> availableCertProfiles = new ArrayList<>();
                                    Integer defaultCertProfileId = endEntityProfile.getDefaultCertificateProfile();
                                    for (int currentCertProfileId : endEntityProfile.getAvailableCertificateProfileIds()) {
                                        Integer replacementCertProfileId = certificateProfileIdMapping.get(currentCertProfileId);
                                        if (replacementCertProfileId != null) {
                                            if (replacementCertProfileId != currentCertProfileId) {
                                                getLogger().warn("Replacing cert profile with id " + currentCertProfileId + " with " + replacementCertProfileId + ".");
                                            }
                                            availableCertProfiles.add(replacementCertProfileId);
                                            if (currentCertProfileId == defaultCertProfileId) {
                                                defaultCertProfileId = replacementCertProfileId;
                                            }
                                        } else {
                                            if (getCertificateProfileSession().getCertificateProfile(currentCertProfileId) != null || CertificateProfileConstants.isFixedCertificateProfile(currentCertProfileId)) {
                                                availableCertProfiles.add(currentCertProfileId);
                                            } else {
                                                getLogger().warn("End Entity Profile '" + profileInfo.getProfileName() + "' references certificate profile " + currentCertProfileId + " that does not exist.");
                                                if (currentCertProfileId == defaultCertProfileId) {
                                                    defaultCertProfileId = null;
                                                }
                                            }
                                        }
                                    }
                                    if (availableCertProfiles.isEmpty()) {
                                        getLogger().warn("End Entity Profile '" + profileInfo.getProfileName() + "' only references certificate profile(s) that does not exist. Using ENDUSER profile.");
                                        availableCertProfiles.add(EndEntityConstants.EMPTY_END_ENTITY_PROFILE); // At least make sure the default profile is available
                                    }
                                    if (defaultCertProfileId == null) {
                                        // Use first available profile from list as default if original default was missing
                                        defaultCertProfileId = availableCertProfiles.get(0);
                                    }
                                    endEntityProfile.setAvailableCertificateProfileIds(availableCertProfiles);
                                    endEntityProfile.setDefaultCertificateProfile(defaultCertProfileId);

                                    // Remove any unknown CA and break if none is left
                                    Integer defaultCA = endEntityProfile.getDefaultCA();
                                    final List<Integer> cas = endEntityProfile.getAvailableCAs();
                                    final List<Integer> availableCAs = new ArrayList<>();
                                    for (int currentCaId : cas) {
                                        // The constant ALLCAS will not be searched for among available CAs
                                        if (currentCaId != SecConst.ALLCAS) {
                                            if (!getCaSession().existsCa(currentCaId)) {
                                                getLogger().warn("CA with id " + currentCaId + " was not found and will not be used in end entity profile '" + profileInfo.getProfileName() + "'.");
                                                if (defaultCA == currentCaId) {
                                                    defaultCA = null;
                                                }
                                            } else {
                                                availableCAs.add(currentCaId);
                                            }
                                        } else {
                                            availableCAs.add(SecConst.ALLCAS);
                                        }
                                    }
                                    if (availableCAs.isEmpty()) {
                                        if (caId == null) {
                                            getLogger().error("No CAs left in end entity profile '" + profileInfo.getProfileName() + "' and no CA specified on command line. Using ALLCAs.");
                                            availableCAs.add(SecConst.ALLCAS);
                                        } else {
                                            availableCAs.add(caId);
                                            getLogger().warn("No CAs left in end entity profile '" + profileInfo.getProfileName() + "'. Using CA supplied on command line with id '" + caId + "'.");
                                        }
                                    }
                                    if (defaultCA == null) {
                                        defaultCA = availableCAs.get(0); // Use first available
                                        getLogger().warn("Changing default CA in end entity profile '" + profileInfo.getProfileName() + "' to " + defaultCA + ".");
                                    }
                                    endEntityProfile.setAvailableCAs(availableCAs);
                                    endEntityProfile.setDefaultCA(defaultCA);
                                    try {
                                        getEndEntityProfileSession().addEndEntityProfile(getAuthenticationToken(), profileInfo.getProfileId(), profileInfo.getProfileName(), endEntityProfile);
                                        getLogger().info("Added entity profile '" + profileInfo.getProfileName() + "' to database.");
                                    } catch (EndEntityProfileExistsException e) {
                                        getLogger().error("Error adding entity profile '" + profileInfo.getProfileName() + "' to database.");
                                        getLogger().error("Error", e);
                                    }
                                } else {
                                    // Add certificate profile
                                    final CertificateProfile certificateProfile = new CertificateProfile();
                                    certificateProfile.loadData(loadedObject);
                                    // Make sure CAs in profile exist
                                    List<Integer> cas = certificateProfile.getAvailableCAs();
                                    if (cas == null) {
                                        cas = new ArrayList<>();
                                    }
                                    ArrayList<Integer> casToRemove = new ArrayList<>();
                                    for (Integer currentCA : cas) {
                                        // If the CA is not ANYCA and the CA does not exist, remove it from the profile before import
                                        if (currentCA != CertificateProfile.ANYCA) {
                                            if (!getCaSession().existsCa(currentCA)) {
                                                casToRemove.add(currentCA);
                                            }
                                        }
                                    }
                                    for (Integer toRemove : casToRemove) {
                                        getLogger().warn("CA with id " + toRemove + " was not found and will not be used in certificate profile '" + profileInfo.getProfileName() + "'.");
                                        cas.remove(toRemove);
                                    }
                                    if (cas.size() == 0) {
                                        if (caId == null) {
                                            getLogger().error("No CAs left in certificate profile '" + profileInfo.getProfileName() + "' and no CA specified on command line. Using ANYCA.");
                                            cas.add(CertificateProfile.ANYCA);
                                        } else {
                                            getLogger().warn("No CAs left in certificate profile '" + profileInfo.getProfileName() + "'. Using CA supplied on command line with id '" + caId + "'.");
                                            cas.add(caId);
                                        }
                                    }
                                    certificateProfile.setAvailableCAs(cas);
                                    // Remove and warn about unknown publishers
                                    List<Integer> publisherIds = certificateProfile.getPublisherList();
                                    ArrayList<Integer> publisherIdsToRemove = new ArrayList<>();
                                    for (Integer publisherId : publisherIds) {
                                        BasePublisher pub = null;
                                        try {
                                            pub = getPublisherSession().getPublisher(publisherId);
                                        } catch (Exception e) {
                                            getLogger().warn("There was an error loading publisher with id " + publisherId + ". Use debug logging to see stack trace: " + e.getMessage());
                                            getLogger().debug("Full stack trace: ", e);
                                        }
                                        if (pub == null) {
                                            publisherIdsToRemove.add(publisherId);
                                        }
                                    }
                                    for (Integer publisherIdToRemove : publisherIdsToRemove) {
                                        getLogger().warn("Publisher with id " + publisherIdToRemove + " was not found and will not be used in certificate profile '" + profileInfo.getProfileName() + "'.");
                                        publisherIds.remove(publisherIdToRemove);
                                    }
                                    certificateProfile.setPublisherList(publisherIds);
                                    // Add profile
                                    try {
                                        if (profileInfo.getProfileId() == -1) {
                                            // id already existed, we need to create a new one
                                            final int newProfileid = getCertificateProfileSession().addCertificateProfile(getAuthenticationToken(), profileInfo.getProfileName(), certificateProfile);
                                            // make a mapping from the old id (that was already in use) to the new one so we can change end entity profiles
                                            certificateProfileIdMapping.put(profileInfo.getOriginalProfileId(), newProfileid);
                                        } else {
                                            getCertificateProfileSession().addCertificateProfile(getAuthenticationToken(), profileInfo.getProfileId(), profileInfo.getProfileName(), certificateProfile);
                                        }
                                        // Make a mapping from the new to the new id, so we have a mapping if the profile id did not change at all
                                        certificateProfileIdMapping.put(profileInfo.getProfileId(), getCertificateProfileSession().getCertificateProfileId(profileInfo.getProfileName()));
                                        getLogger().info("Added certificate profile '" + profileInfo.getProfileName() + "', '" + profileInfo.getProfileId() + "' to database.");
                                    } catch (CertificateProfileExistsException e) {
                                        getLogger().error("Error adding certificate profile '" + profileInfo.getProfileName() + "', '" + profileInfo.getProfileId() + "' to database.");
                                    }
                                }
                            }
                            else {
                                commandResult = CommandResult.FUNCTIONAL_FAILURE;
                            }
                        }
                    }
                }
            }
        } catch (AuthorizationDeniedException e) {
            log.error("Current CLI user doesn't have sufficient privileges to import profiles.");
            return CommandResult.AUTHORIZATION_FAILURE;
        } catch (IllegalStateException e) {
            log.error("CLI execution got a general failure.");
            return CommandResult.CLI_FAILURE;
        }
        return commandResult;
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

    private class ProfileInfo {

        private final String profileName;
        private final int originalProfileId;
        private int profileId;
        private final boolean isCertificateProfile;
        private final boolean isEntityProfile;
        private boolean hasError = false;

        ProfileInfo(final String profileName, final int profileId, final boolean isCertificateProfile, final boolean isEntityProfile) {
            this.profileName = profileName;
            this.originalProfileId = profileId;
            this.profileId = profileId;
            this.isCertificateProfile = isCertificateProfile;
            this.isEntityProfile = isEntityProfile;
        }

        String getProfileName() {
            return profileName;
        }

        int getProfileId() {
            return profileId;
        }

        void setProfileId(final int profileId) {
            this.profileId = profileId;
        }

        int getOriginalProfileId() {
            return originalProfileId;
        }

        boolean isEntityProfile() {
            return isEntityProfile;
        }

        void setError(final boolean hasError) {
            this.hasError = hasError;
        }

        boolean isOk() {
            return !hasError;
        }
    }

    private ProfileInfo getProfileInfoFromFileName(final String fileName) {
        if(StringUtils.isNotEmpty(fileName)) {
            final boolean isCertificateProfile = fileName.contains("certprofile_");
            final boolean isEntityProfile = fileName.contains("entityprofile_");
            if(!isCertificateProfile && !isEntityProfile) {
                return null;
            }
            int profileNameBeginIndex = fileName.indexOf("_");
            int profileNameSeparatorIndex = fileName.lastIndexOf("-");
            int profileIdEndIndex = fileName.lastIndexOf(".xml");
            if (profileNameBeginIndex < 0 || profileNameSeparatorIndex < 0 || profileIdEndIndex < 0) {
                getLogger().error("Filename not as expected (cert/entityprofile_<name>-<id>.xml).");
                return null;
            } else {
                try {
                    final String profileName = URLDecoder.decode(fileName.substring(profileNameBeginIndex + 1, profileNameSeparatorIndex), "UTF-8");
                    final int profileId = Integer.parseInt(fileName.substring(profileNameSeparatorIndex + 1, profileIdEndIndex));
                    return new ProfileInfo(profileName, profileId, isCertificateProfile, isEntityProfile);
                } catch (UnsupportedEncodingException e) {
                    getLogger().error("UTF-8 was not a known character encoding.");
                } catch (NumberFormatException e) {
                    getLogger().error("Profile ID is not a number.");
                }
            }
        }
        return null;
    }

    private ProfileInfo checkIfProfileExists(final ProfileInfo profileInfo) {
        final String profileName = profileInfo.getProfileName();
        final int profileId = profileInfo.getProfileId();
        if (profileInfo.isEntityProfile) {
            if (getEndEntityProfileSession().getEndEntityProfile(profileName) != null) {
                getLogger().error("Entity profile '" + profileName + "' already exist in database.");
                profileInfo.setError(true);
            } else if (getEndEntityProfileSession().getEndEntityProfile(profileId) != null) {
                int freeEndEntityProfileId = getEndEntityProfileSession().findFreeEndEntityProfileId();
                getLogger().warn("Entity profileid '" + profileId + "' already exist in database. Using '" + freeEndEntityProfileId + "' instead.");
                profileInfo.setProfileId(freeEndEntityProfileId);
            }
        }
        if(profileInfo.isCertificateProfile) {
            if (getCertificateProfileSession().getCertificateProfileId(profileName) != CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                getLogger().error("Certificate profile '" + profileName + "' already exist in database.");
                profileInfo.setError(true);
            } else if (getCertificateProfileSession().getCertificateProfile(profileId) != null) {
                getLogger().warn("Certificate profile id '" + profileId + "' already exist in database. Adding with a new profile id instead.");
                // means we should create a new id when adding the cert profile
                profileInfo.setProfileId(-1);
            }
        }
        return profileInfo;
    }

    private CaSessionRemote getCaSession() {
        if(caSession == null) {
            caSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class);
        }
        return caSession;
    }

    private CertificateProfileSessionRemote getCertificateProfileSession() {
        if(certificateProfileSession == null) {
            certificateProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class);
        }
        return certificateProfileSession;
    }

    private EndEntityProfileSessionRemote getEndEntityProfileSession() {
        if(endEntityProfileSession == null) {
            endEntityProfileSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class);
        }
        return endEntityProfileSession;
    }

    private PublisherSessionRemote getPublisherSession() {
        if(publisherSession == null) {
            publisherSession = EjbRemoteHelper.INSTANCE.getRemoteSession(PublisherSessionRemote.class);
        }
        return publisherSession;
    }
}
