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

package org.ejbca.ui.cli.ra;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.config.GlobalConfigurationSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.ui.cli.CliUsernameException;
import org.ejbca.ui.cli.ErrorAdminCommandException;

/**
 * Adds a user to the database.
 * 
 * @version $Id$
 */
public class RaAddUserCommand extends BaseRaAdminCommand {

    private static final String USERGENERATED = "USERGENERATED";
    private static final String P12 = "P12";
    private static final String JKS = "JKS";
    private static final String PEM = "PEM";

    private final String[] softtokennames = { USERGENERATED, P12, JKS, PEM };
    private final int[] softtokenids = { SecConst.TOKEN_SOFT_BROWSERGEN, SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM };

    public String getMainCommand() {
        return MAINCOMMAND;
    }

    public String getSubCommand() {
        return "adduser";
    }

    public String getDescription() {
        return "Adds a user";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            args = parseUsernameAndPasswordFromArgs(args);
        } catch (CliUsernameException e) {
            return;
        }
        
        try {
            GlobalConfiguration globalconfiguration = ejb.getRemoteSession(GlobalConfigurationSessionRemote.class).getCachedGlobalConfiguration();
            boolean usehardtokens = globalconfiguration.getIssueHardwareTokens();
            boolean usekeyrecovery = globalconfiguration.getEnableKeyRecovery();
            String[] hardtokenissueraliases = null;
            Collection<Integer> authorizedhardtokenprofiles = null;
            HashMap<Integer, String> hardtokenprofileidtonamemap = null;

            if (usehardtokens) {
                hardtokenissueraliases = (String[]) ejb.getRemoteSession(HardTokenSessionRemote.class).getHardTokenIssuerAliases(getAdmin(cliUserName, cliPassword)).toArray(new String[0]);

                authorizedhardtokenprofiles = ejb.getRemoteSession(HardTokenSessionRemote.class).getAuthorizedHardTokenProfileIds(getAdmin(cliUserName, cliPassword));
                hardtokenprofileidtonamemap = ejb.getRemoteSession(HardTokenSessionRemote.class).getHardTokenProfileIdToNameMap(getAdmin(cliUserName, cliPassword));
            }

            String types = "Type (mask): INVALID=0; END-USER=1; SENDNOTIFICATION=256; PRINTUSERDATA=512";
            if (usekeyrecovery) {
                types = "Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256; PRINTUSERDATA=512";
            }

            if ((args.length < 9) || (args.length > 12)) {
                getLogger().info("Description: " + getDescription());
                Collection<Integer> caids = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCAs(getAdmin(cliUserName, cliPassword));
                Collection<String> canames = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAvailableCANames(getAdmin(cliUserName, cliPassword));
                Collection<Integer> certprofileids = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getAuthorizedCertificateProfileIds(CertificateConstants.CERTTYPE_ENDENTITY, caids);
                Map<Integer, String> certificateprofileidtonamemap = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileIdToNameMap();

                Collection<Integer> endentityprofileids = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(getAdmin(cliUserName, cliPassword));
                Map<Integer, String> endentityprofileidtonamemap = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileIdToNameMap();

                if (usehardtokens) {
                    getLogger().info(
                            "Usage: " + getCommand() + " <username> <password> <dn>"
                                    + " <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] [<hardtokenissuer>]");
                } else {
                    getLogger().info(
                            "Usage: " + getCommand() + " <username> <password> <dn>"
                                    + " <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] ");
                }
                getLogger().info("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
                getLogger().info(
                        "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>,"
                                + " ipaddress=<address>, upn=<MS UPN>, guid=<MS globally unique id>, directoryName=<LDAP escaped DN>,"
                                + " krb5principal=<Krb5 principal name>\"");
                getLogger().info("An LDAP escaped DN is for example:");
                getLogger().info("DN: CN=Tomas Gustavsson, O=PrimeKey Solutions, C=SE");
                getLogger().info("LDAP escaped DN: CN=Tomas Gustavsson\\, O=PrimeKey Solutions\\, C=SE");

                getLogger().info(types);

                String hardTokenString = "";
                if (usehardtokens) {
                    Iterator<Integer> iter = authorizedhardtokenprofiles.iterator();
                    while (iter.hasNext()) {
                        hardTokenString += (hardTokenString.length() == 0 ? "" : ", ") + hardtokenprofileidtonamemap.get(iter.next());
                    }
                }
                getLogger().info("Existing tokens      : " + USERGENERATED + ", " + P12 + ", " + JKS + ", " + PEM + ", " + hardTokenString);

                String existingCas = "";
                Iterator<String> nameiter = canames.iterator();
                while (nameiter.hasNext()) {
                    existingCas += (existingCas.length() == 0 ? "" : ", ") + nameiter.next();
                }
                getLogger().info("Existing cas  : " + existingCas);

                String existingCps = "";
                Iterator<Integer> iter = certprofileids.iterator();
                while (iter.hasNext()) {
                    existingCps += (existingCps.length() == 0 ? "" : ", ") + certificateprofileidtonamemap.get(iter.next());
                }
                getLogger().info("Existing certificate profiles  : " + existingCps);

                String existingEeps = "";
                iter = endentityprofileids.iterator();
                while (iter.hasNext()) {
                    existingEeps += (existingEeps.length() == 0 ? "" : ", ") + endentityprofileidtonamemap.get(iter.next());
                }
                getLogger().info("Existing endentity profiles  : " + existingEeps);

                String existingHtis = "";
                if (usehardtokens && hardtokenissueraliases.length > 0) {
                    for (int i = 0; i < hardtokenissueraliases.length; i++) {
                        existingHtis += (existingHtis.length() == 0 ? "" : ", ") + hardtokenissueraliases[i];
                    }
                }
                getLogger().info("Existing hardtoken issuers  : " + existingHtis);
                getLogger().info("If the user does not have a SubjectAltName or an email address,");
                getLogger().info("or you want the password to be auto-generated use the value 'null'.");
                return;
            }

            String username = args[1];
            String password = args[2];
            String dn = args[3];
            String subjectaltname = args[4];
            String caname = args[5];
            String email = args[6];
            int type = 1;
            try {
                type = Integer.parseInt(args[7]);
            } catch (NumberFormatException e) {
                throw new NumberFormatException("Invalid type, '" + args[7] + "'.\n" + types);
            }
            String tokenname = args[8];
            int profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            boolean error = false;
            boolean usehardtokenissuer = false;

            int caid = 0;
            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAdmin(cliUserName, cliPassword), caname).getCAId();
            } catch (CADoesntExistsException e) {
                // NOPMD: let it be 0, we will print a suitable error message below
            }            

            if (args.length > 9) {
                // Use certificate type, no end entity profile.
                certificatetypeid = ejb.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(args[9]);
                getLogger().info("Using certificate profile: " + args[9] + ", with id: " + certificatetypeid);
            }

            if (args.length > 10) {
                // Use certificate type and end entity profile.
                profileid = ejb.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileId(args[10]);
                getLogger().info("Using entity profile: " + args[10] + ", with id: " + profileid);
            }

            if (args.length == 12 && usehardtokens) {
                // Use certificate type, end entity profile and hardtokenissuer.
                hardtokenissuerid = ejb.getRemoteSession(HardTokenSessionRemote.class).getHardTokenIssuerId(getAdmin(cliUserName, cliPassword), args[11]);
                usehardtokenissuer = true;
                getLogger().info("Using hard token issuer: " + args[11] + ", with id: " + hardtokenissuerid);
            }

            int tokenid = getTokenId(getAdmin(cliUserName, cliPassword), tokenname, usehardtokens, ejb.getRemoteSession(HardTokenSessionRemote.class));
            if (tokenid == 0) {
                getLogger().error("Invalid token id.");
                error = true;
            }

            if (certificatetypeid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) { 
            	// Certificate profile not found in database.
                getLogger().error("Could not find certificate profile in database.");
                error = true;
            }

            if (profileid == 0) { // End entity profile not found i database.
                getLogger().error("Could not find end entity profile in database.");
                error = true;
            }

            if (caid == 0) { // CA not found i database.
                getLogger().error("Could not find CA '"+caname+"'in database.");
                error = true;
            }

            if (usehardtokenissuer && hardtokenissuerid == SecConst.NO_HARDTOKENISSUER) {
                getLogger().error("Could not find hard token issuer in database.");
                error = true;
            }

            if ((tokenid > SecConst.TOKEN_SOFT) && (hardtokenissuerid == SecConst.NO_HARDTOKENISSUER)) {
                getLogger().error("HardTokenIssuer has to be choosen when user with hard tokens is added.");
                error = true;
            }

            if (email.equalsIgnoreCase("NULL") && ((type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION)) {
                getLogger().error("Email field cannot be null when send notification type is given.");
                error = true;
            }

            // Check if username already exists.
            if (ejb.getRemoteSession(UserAdminSessionRemote.class).existsUser(username)) {
                getLogger().error("User already exists in the database.");
                error = true;
            }

            if (!error) {
                getLogger().info("Trying to add user:");
                getLogger().info("Username: " + username);
                getLogger().info("Password: <password hidden>");
                getLogger().info("DN: " + dn);
                getLogger().info("CA Name: " + caname);
                getLogger().info("SubjectAltName: " + subjectaltname);
                getLogger().info("Email: " + email);
                getLogger().info("Type: " + type);
                getLogger().info("Token: " + tokenname);
                getLogger().info("Certificate profile: " + certificatetypeid);
                getLogger().info("End entity profile: " + profileid);
                if (password.toUpperCase().equals("NULL")) {
                    password = null;
                }
                if (subjectaltname.toUpperCase().equals("NULL")) {
                    subjectaltname = null;
                }
                if (email.toUpperCase().equals("NULL")) {
                    email = null;
                }
                try {
                    ejb.getRemoteSession(UserAdminSessionRemote.class).addUser(getAdmin(cliUserName, cliPassword), username, password, dn, subjectaltname, email, false, profileid, certificatetypeid, type, tokenid,
                            hardtokenissuerid, caid);
                    getLogger().info("User '" + username + "' has been added.");
                    getLogger().info("Note: If batch processing should be possible, also use 'ra setclearpwd " + username + " <pwd>'.");
                } catch (AuthorizationDeniedException e) {
                    getLogger().error(e.getMessage());
                } catch (UserDoesntFullfillEndEntityProfile e) {
                    getLogger().info("Given userdata doesn't fullfill end entity profile. : " + e.getMessage());
                } catch (WaitingForApprovalException e) {
                    getLogger().info("\nOperation pending, waiting for approval: " + e.getMessage());
                } catch (ApprovalException e) {
                    getLogger().info("\nApproval exception: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    /**
     * Returns the tokenid type of the user, returns 0 if invalid tokenname.
     */
    private int getTokenId(AuthenticationToken administrator, String tokenname, boolean usehardtokens, HardTokenSessionRemote hardtokensession) {
        int returnval = 0;
        // First check for soft token type
        for (int i = 0; i < softtokennames.length; i++) {
            if (softtokennames[i].equals(tokenname)) {
                returnval = softtokenids[i];
                break;
            }
        }
        if (returnval == 0 && usehardtokens) {
            returnval = hardtokensession.getHardTokenProfileId(administrator, tokenname);
        }
        return returnval;
    }
}
