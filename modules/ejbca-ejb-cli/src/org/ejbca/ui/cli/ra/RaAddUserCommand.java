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

import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.store.CertificateStoreSessionRemote;
import org.ejbca.core.ejb.hardtoken.HardTokenSessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
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

    private CertificateStoreSessionRemote certificateStoreSession = ejb.getCertStoreSession();
    private HardTokenSessionRemote hardTokenSession = ejb.getHardTokenSession();
    private RaAdminSessionRemote raAdminSession = ejb.getRAAdminSession();
    private UserAdminSessionRemote userAdminSession = ejb.getUserAdminSession();
    private CAAdminSessionRemote caAdminSession = ejb.getCAAdminSession();

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
            GlobalConfiguration globalconfiguration = raAdminSession.loadGlobalConfiguration(getAdmin());
            boolean usehardtokens = globalconfiguration.getIssueHardwareTokens();
            boolean usekeyrecovery = globalconfiguration.getEnableKeyRecovery();
            String[] hardtokenissueraliases = null;
            Collection authorizedhardtokenprofiles = null;
            HashMap hardtokenprofileidtonamemap = null;

            if (usehardtokens) {
                hardtokenissueraliases = (String[]) hardTokenSession.getHardTokenIssuerAliases(getAdmin()).toArray(new String[0]);

                authorizedhardtokenprofiles = hardTokenSession.getAuthorizedHardTokenProfileIds(getAdmin());
                hardtokenprofileidtonamemap = hardTokenSession.getHardTokenProfileIdToNameMap(getAdmin());
            }

            String types = "Type (mask): INVALID=0; END-USER=1; SENDNOTIFICATION=256; PRINTUSERDATA=512";
            if (usekeyrecovery) {
                types = "Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256; PRINTUSERDATA=512";
            }

            if ((args.length < 9) || (args.length > 12)) {
                getLogger().info("Description: " + getDescription());
                Collection caids = caAdminSession.getAvailableCAs(getAdmin());
                HashMap caidtonamemap = caAdminSession.getCAIdToNameMap(getAdmin());

                Collection certprofileids = certificateStoreSession.getAuthorizedCertificateProfileIds(getAdmin(), SecConst.CERTTYPE_ENDENTITY, caids);
                HashMap certificateprofileidtonamemap = certificateStoreSession.getCertificateProfileIdToNameMap(getAdmin());

                Collection endentityprofileids = raAdminSession.getAuthorizedEndEntityProfileIds(getAdmin());
                HashMap endentityprofileidtonamemap = raAdminSession.getEndEntityProfileIdToNameMap(getAdmin());

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
                    Iterator iter = authorizedhardtokenprofiles.iterator();
                    while (iter.hasNext()) {
                        hardTokenString += (hardTokenString.length() == 0 ? "" : ", ") + hardtokenprofileidtonamemap.get(iter.next());
                    }
                }
                getLogger().info("Existing tokens      : " + USERGENERATED + ", " + P12 + ", " + JKS + ", " + PEM + hardTokenString);

                String existingCas = "";
                Iterator iter = caids.iterator();
                while (iter.hasNext()) {
                    existingCas += (existingCas.length() == 0 ? "" : ", ") + caidtonamemap.get(iter.next());
                }
                getLogger().info("Existing cas  : " + existingCas);

                String existingCps = "";
                iter = certprofileids.iterator();
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
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            boolean error = false;
            boolean usehardtokenissuer = false;

            int caid = 0;
            try {
                caid = caAdminSession.getCAInfo(getAdmin(), caname).getCAId();
            } catch (Exception e) {
            }

            if (args.length > 9) {
                // Use certificate type, no end entity profile.
                certificatetypeid = certificateStoreSession.getCertificateProfileId(getAdmin(), args[9]);
                getLogger().info("Using certificate profile: " + args[9] + ", with id: " + certificatetypeid);
            }

            if (args.length > 10) {
                // Use certificate type and end entity profile.
                profileid = raAdminSession.getEndEntityProfileId(getAdmin(), args[10]);
                getLogger().info("Using entity profile: " + args[10] + ", with id: " + profileid);
            }

            if (args.length == 12 && usehardtokens) {
                // Use certificate type, end entity profile and hardtokenissuer.
                hardtokenissuerid = hardTokenSession.getHardTokenIssuerId(getAdmin(), args[11]);
                usehardtokenissuer = true;
                getLogger().info("Using hard token issuer: " + args[11] + ", with id: " + hardtokenissuerid);
            }

            int tokenid = getTokenId(getAdmin(), tokenname, usehardtokens, hardTokenSession);
            if (tokenid == 0) {
                getLogger().error("Invalid token id.");
                error = true;
            }

            if (certificatetypeid == SecConst.PROFILE_NO_PROFILE) { // Certificate
                // profile
                // not found
                // i
                // database.
                getLogger().error("Couldn't find certificate profile in database.");
                error = true;
            }

            if (profileid == 0) { // End entity profile not found i database.
                getLogger().error("Couldn't find end entity profile in database.");
                error = true;
            }

            if (caid == 0) { // CA not found i database.
                getLogger().error("Couldn't find CA in database.");
                error = true;
            }

            if (usehardtokenissuer && hardtokenissuerid == SecConst.NO_HARDTOKENISSUER) {
                getLogger().error("Couldn't find hard token issuer in database.");
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
            if (userAdminSession.existsUser(getAdmin(), username)) {
                getLogger().error("User already exists in the database.");
                error = true;
            }

            if (!error) {
                getLogger().info("Trying to add user:");
                getLogger().info("Username: " + username);
                getLogger().info("Password (hashed only): " + password);
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
                    userAdminSession.addUser(getAdmin(), username, password, dn, subjectaltname, email, false, profileid, certificatetypeid, type, tokenid,
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
    private int getTokenId(Admin administrator, String tokenname, boolean usehardtokens, HardTokenSessionRemote hardtokensession) {
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
