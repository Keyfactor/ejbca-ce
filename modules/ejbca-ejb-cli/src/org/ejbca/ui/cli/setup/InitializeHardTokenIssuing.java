/*************************************************************************
 *                                                                       *
 *  EJBCA: The OpenSource Certificate Authority                          *
 *                                                                       *
 *  This software is free software; you can redistribute it and/or       *
 *  modify it under the terms of the GNU Lesser General Public           *
 *  License as published by the Free Software Foundation; either         *
 *  version 2.1 of the License, or any later version.                    *
 *                                                                       *
 *  See terms of license at gnu.org.                                     *
 *                                                                       *
 *************************************************************************/

package org.ejbca.ui.cli.setup;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;
import java.util.List;

import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.authorization.AdminGroup;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.profiles.IPINEnvelopeSettings;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Class used for easy setup primecard server.
 * 
 * This isn't used as a command line but used from within, it's run by the
 * command "setup initializehardtokenissuing"
 * 
 * It's main method run sets up: 1. Sets the global setting use hard token
 * functionality to true. 2. A default 'Administrator Token' Hard Profile Token
 * 3. A default 'Local' Hard Token Issuer with the 'Temporary Super Admin Group'
 * as admin group. 4. Adds a 'Administrator Token End Entity Profile' End Entity
 * Profile with the following fields: * CN, required * 'Administrator Token' as
 * default and available tokens * 'local' as default and available issuers *
 * default available CA is taken from parameter to run method
 * 
 * 5. Adds a user SuperAdminToken with CN=SuperAdminToken with issuer local 6.
 * Adds SuperAdminToken to Temporary Super Admin Group
 * 
 * After run have been executed should it be easy to run primecard locally to
 * just issue the first card.
 * 
 * @author Philip Vendil
 * @version $Id: InitializeHardTokenIssuing.java 8119 2009-10-17 00:33:15Z
 *          jeklund $
 * 
 */
public class InitializeHardTokenIssuing extends BaseCommand {

    private static final String SVGPINFILENAME = "src/cli/admincard_pintemplate.svg";
    private static final String ADMINTOKENPROFILENAME = "Administrator Token Profile";
    private static final String ISSUERALIAS = "local";
    private static final String SUPERADMINTOKENNAME = "SuperAdminToken";
    private static final String ADMINTOKENENDENTITYPROFILE = "Administration Token End Entity Profile";

    public String getMainCommand() {
        return "setup";
    }

    public String getSubCommand() {
        return "initializehardtokenissuing";
    }

    public String getDescription() {
        return "Used for easy setup primecard server";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        if (args.length < 2) {
            getLogger().info("Description: " + getDescription());
            getLogger().info("Usage: " + getCommand() + " <caname>");
            return;
        }
        String caname = args[1];
        try {
            runSetup(caname);
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    /**
     * See class header for explanation.
     */
    private void runSetup(String caname) throws Exception {
        getLogger().info("Adding Hard Token Super Administrator .....\n\n");
        int caid = ejb.getCaSession().getCAInfo(getAdmin(), caname).getCAId();
        int admingroupid = ejb.getRoleAccessSession().getAdminGroup(getAdmin(), AdminGroup.TEMPSUPERADMINGROUP).getRoleDataId();

        configureGlobalConfiguration();
        createAdministratorTokenProfile();
        createLocalHardTokenIssuer(admingroupid);
        createAdminTokenEndEntityProfile(caid);
        createSuperAdminTokenUser(caid);
        addSuperAdminTokenUserToTemporarySuperAdminGroup(caid);

        getLogger()
                .info(
                        "A hard token Administrator have been added.\n\n" + "In order to issue the card. Startup PrimeCard in local mode using\n"
                                + "the alias 'local'. Then insert an empty token.\n"
                                + "This Administrator is also a super administrator for the EJBCA installation.\n");
    }

    /**
     * Sets the Issue Hard Tokens flag to true in the system configuration.
     * 
     * @throws Exception
     */
    private void configureGlobalConfiguration() throws Exception {
    	ejb.getGlobalConfigurationSession().setSettingIssueHardwareTokens(getAdmin(), true);
    }

    /**
     * Creates the 'Administrator Token' Hard Token Profile
     * 
     * @throws Exception
     */
    private void createAdministratorTokenProfile() throws Exception {
        SwedishEIDProfile admintokenprofile = new SwedishEIDProfile();

        admintokenprofile.setPINEnvelopeType(IPINEnvelopeSettings.PINENVELOPETYPE_GENERALENVELOBE);

        BufferedReader br = new BufferedReader(new FileReader(SVGPINFILENAME));
        String filecontent = "";
        String nextline = "";
        while (nextline != null) {
            nextline = br.readLine();
            if (nextline != null) {
                filecontent += nextline + "\n";
            }
        }
        ((IPINEnvelopeSettings) admintokenprofile).setPINEnvelopeData(filecontent);
        ((IPINEnvelopeSettings) admintokenprofile).setPINEnvelopeTemplateFilename(SVGPINFILENAME);

        this.ejb.getHardTokenSession().addHardTokenProfile(getAdmin(), ADMINTOKENPROFILENAME, admintokenprofile);
    }

    /**
     * Creates the 'Local' Hard Token Issuer
     * 
     * @throws Exception
     */
    private void createLocalHardTokenIssuer(int admingroupid) throws Exception {
        HardTokenIssuer localissuer = new HardTokenIssuer();

        localissuer.setDescription("Issuer created by installation script, used to create the first administration token");

        ArrayList<Integer> availableprofiles = new ArrayList<Integer>();
        availableprofiles.add(Integer.valueOf(ejb.getHardTokenSession().getHardTokenProfileId(getAdmin(), ADMINTOKENPROFILENAME)));
        localissuer.setAvailableHardTokenProfiles(availableprofiles);

        this.ejb.getHardTokenSession().addHardTokenIssuer(getAdmin(), ISSUERALIAS, admingroupid, localissuer);

    }

    /**
     * Creates the End Entity Profile used for issuing the superadmintoken
     * 
     * @throws Exception
     */
    private void createAdminTokenEndEntityProfile(int caid) throws Exception {
        int tokenid = ejb.getHardTokenSession().getHardTokenProfileId(getAdmin(), ADMINTOKENPROFILENAME);
        int hardtokenissuerid = ejb.getHardTokenSession().getHardTokenIssuerId(getAdmin(), ISSUERALIAS);
        EndEntityProfile profile = new EndEntityProfile();

        // Set autogenerated password
        profile.setUse(EndEntityProfile.PASSWORD, 0, false);

        // Batch
        profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setRequired(EndEntityProfile.CLEARTEXTPASSWORD, 0, true);
        profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD, 0, EndEntityProfile.TRUE);

        // Set CA
        profile.setValue(EndEntityProfile.DEFAULTCA, 0, "" + caid);
        profile.setValue(EndEntityProfile.AVAILCAS, 0, "" + caid);

        profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE, 0, "" + SecConst.CERTPROFILE_FIXED_ENDUSER);
        profile.setValue(EndEntityProfile.AVAILCERTPROFILES, 0, "" + SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH + ";"
                + SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENENC);

        // Set Default Token Type
        profile.setValue(EndEntityProfile.DEFKEYSTORE, 0, "" + tokenid);
        profile.setValue(EndEntityProfile.AVAILKEYSTORE, 0, "" + tokenid);

        // Set Default Issuers
        profile.setUse(EndEntityProfile.AVAILTOKENISSUER, 0, true);

        profile.setValue(EndEntityProfile.DEFAULTTOKENISSUER, 0, "" + hardtokenissuerid);
        profile.setValue(EndEntityProfile.AVAILTOKENISSUER, 0, "" + hardtokenissuerid);

        // Save Profile
        this.ejb.getEndEntityProfileSession().addEndEntityProfile(getAdmin(), ADMINTOKENENDENTITYPROFILE, profile);
    }

    /**
     * Adds a new superadmintoken user to the user database and puts it to the
     * local issuer queue.
     * 
     * @throws Exception
     */
    private void createSuperAdminTokenUser(int caid) throws Exception {
        int endentityprofileid = ejb.getEndEntityProfileSession().getEndEntityProfileId(getAdmin(), ADMINTOKENENDENTITYPROFILE);
        int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
        int tokenid = ejb.getHardTokenSession().getHardTokenProfileId(getAdmin(), ADMINTOKENPROFILENAME);
        int hardtokenissuerid = ejb.getHardTokenSession().getHardTokenIssuerId(getAdmin(), ISSUERALIAS);

        this.ejb.getUserAdminSession().addUser(getAdmin(), SUPERADMINTOKENNAME, null, "CN=" + SUPERADMINTOKENNAME, null, null, true, endentityprofileid,
                certificateprofileid, 65, tokenid, hardtokenissuerid, caid);
    }

    /**
     * Adds the new superadmintoken user to the Temporary Super Admin Group
     * 
     * @throws Exception
     */
    private void addSuperAdminTokenUserToTemporarySuperAdminGroup(int caid) throws Exception {
        List<AdminEntity> adminentities = new ArrayList<AdminEntity>();
        adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME, AdminEntity.TYPE_EQUALCASEINS, SUPERADMINTOKENNAME, caid));
        ejb.getAdminEntitySession().addAdminEntities(getAdmin(), "Temporary Super Administrator Group", adminentities);
    }
}
