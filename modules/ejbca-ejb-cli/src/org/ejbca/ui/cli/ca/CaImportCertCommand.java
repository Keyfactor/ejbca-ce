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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Collection;
import java.util.Date;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CADoesntExistsException;
import org.cesecore.certificates.ca.CAInfo;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.ca.IllegalNameException;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.certificates.certificate.exception.CertificateSerialNumberException;
import org.cesecore.certificates.certificateprofile.CertificateProfileConstants;
import org.cesecore.certificates.certificateprofile.CertificateProfileSessionRemote;
import org.cesecore.certificates.crl.RevocationReasons;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EJBTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.model.ra.AlreadyRevokedException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.RevokeBackDateNotAllowedForProfileException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileNotFoundException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports a certificate file to the database.
 *
 * @version $Id$
 */
public class CaImportCertCommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportCertCommand.class);

    private static final String ENDENTITY_USERNAME_KEY = "--username";
    private static final String ENDENTITY_PASSWORD_KEY = "--password";
    private static final String CA_NAME_KEY = "--caname";
    private static final String ACTIVE_KEY = "-a";
    private static final String E_MAIL_KEY = "--email";
    private static final String FILE_KEY = "-f";
    private static final String EE_PROFILE_KEY = "--eeprofile";
    private static final String CERT_PROFILE_KEY = "--certprofile";
    private static final String OVERRIDE_EXISTING_ENDENTITY = "--overwrite";
    private static final String REVOCATION_REASON = "--revocation-reason";
    private static final String REVOCATION_TIME = "--revocation-time";

    private static final String ACTIVE = "ACTIVE";
    private static final String REVOKED = "REVOKED";

    {
        registerParameter(new Parameter(ENDENTITY_USERNAME_KEY, "Username", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "End entity username"));
        registerParameter(new Parameter(ENDENTITY_PASSWORD_KEY, "Password", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "End entity password."));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the issuing CA."));
        registerParameter(new Parameter(ACTIVE_KEY, ACTIVE + "|" + REVOKED, MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set the status of the imported end entity."));
        registerParameter(new Parameter(FILE_KEY, "Certificate File", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Must be PEM encoded"));
        registerParameter(new Parameter(EE_PROFILE_KEY, "Profile Name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "End Entity Profile to create end entity with. If no profile specified then the EMPTY profile will be used."));
        registerParameter(new Parameter(CERT_PROFILE_KEY, "Profile Name", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Certificate Profile to create end entity with. If no profile specified then the default End Entity profile will be used."));
        registerParameter(new Parameter(E_MAIL_KEY, "E-Mail", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "E-Mail for imported End Entity, if any."));
        registerParameter(new Parameter(OVERRIDE_EXISTING_ENDENTITY, "", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.FLAG,
                "Overwrite an existing end entity even if it was not revoked."));
        registerParameter(new Parameter(REVOCATION_REASON, "Reason", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Revocation reason, if the certificate is to be imported as revoked. Will be set to " + RevocationReasons.UNSPECIFIED.getStringValue() + " if this option is not set."));
        registerParameter(new Parameter(REVOCATION_TIME, CaImportCertDirCommand.DATE_FORMAT, MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Revocation time, if the certificate is to be imported as revoked. Will be set to the current time if this option is not set. Format is "
                        + CaImportCertDirCommand.DATE_FORMAT + ", i.e. 2015.05.04-10:15"));
    }

    @Override
    public String getMainCommand() {
        return "importcert";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        log.trace(">execute()");

        CryptoProviderTools.installBCProviderIfNotAvailable();
        String username = parameters.get(ENDENTITY_USERNAME_KEY);
        String password = parameters.get(ENDENTITY_PASSWORD_KEY);
        String caname = parameters.get(CA_NAME_KEY);
        String active = parameters.get(ACTIVE_KEY);
        String email = parameters.get(E_MAIL_KEY);
        String certfile = parameters.get(FILE_KEY);
        String eeprofile = parameters.get(EE_PROFILE_KEY);
        String certificateprofile = parameters.get(CERT_PROFILE_KEY);
        final String revocationReasonString = parameters.get(REVOCATION_REASON);
        final String revocationTimeString = parameters.get(REVOCATION_TIME);
        EndEntityType endEntityType = EndEntityTypes.ENDUSER.toEndEntityType();
        StringBuilder errorString = new StringBuilder();
        int status;
        RevocationReasons revocationReason = null;
        Date revocationTime = null;
        if (ACTIVE.equalsIgnoreCase(active)) {
            status = CertificateConstants.CERT_ACTIVE;
            if(revocationReasonString != null) {
                log.warn("Revocation reason has been set in spite of certificates being imported as active. Ignoring.");
            }
            if(revocationTimeString != null) {
                log.warn("Revocation time has been set in spite of certificates being imported as active. Ignoring.");
            }
        } else if (REVOKED.equalsIgnoreCase(active)) {
            status = CertificateConstants.CERT_REVOKED;
        
            
            if(revocationReasonString != null) {
                revocationReason = RevocationReasons.getFromCliValue(revocationReasonString.toUpperCase());
                if(revocationReason == null) {
                    log.error("ERROR: " + revocationReasonString + " is not a valid revocation reason.");
                    return CommandResult.CLI_FAILURE;
                }
            } else {
                revocationReason = RevocationReasons.UNSPECIFIED;
            } 
            if (revocationTimeString != null) {
                try {
                    revocationTime = new SimpleDateFormat(CaImportCertDirCommand.DATE_FORMAT).parse(revocationTimeString);
                } catch (ParseException e) {
                    log.error("ERROR: " + revocationTimeString + " was not a valid revocation time.");
                    return CommandResult.CLI_FAILURE;
                }
            } else {
                revocationTime = new Date();
            }
        } else {
            errorString.append("Invalid certificate status, must be " + ACTIVE + " or " + REVOKED + "\n");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        Certificate certificate;
        try {
            certificate = loadcert(certfile);
        } catch (FileNotFoundException e) {
            log.error("File " + certfile + " was not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CertificateException e) {
            log.error("PEM in file " + certfile + " could not be read.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            log.error("File " + certfile + " does not seem to contain a PEM encoded certificate.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        final String fingerprint = CertTools.getFingerprintAsString(certificate);
        if (EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).findCertificateByFingerprintRemote(fingerprint) != null) {
            errorString.append("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' is already present.\n");
        }
        // Certificate has expired, but we are obviously keeping it for archival purposes
        if (CertTools.getNotAfter(certificate).compareTo(new java.util.Date()) < 0) {
            status = CertificateConstants.CERT_ARCHIVED;
        }

        // Check if username already exists.
        EndEntityInformation userdata;
        try {
            userdata = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(), username);
        } catch (AuthorizationDeniedException e) {
            log.error("ERROR: CLI user not authorized to manage end entities.");
            return CommandResult.AUTHORIZATION_FAILURE;
        }
        if ((userdata != null) && !parameters.containsKey(OVERRIDE_EXISTING_ENDENTITY)) {
            if (userdata.getStatus() != EndEntityConstants.STATUS_REVOKED) {
                errorString.append("User " + username + " already exists; only revoked user can be overwritten.\n");
            }
        }

        if (StringUtils.isEmpty(email) || StringUtils.equalsIgnoreCase(email, "null")) {
            email = CertTools.getEMailAddress(certificate);
        }

        int endentityprofileid = EndEntityConstants.EMPTY_END_ENTITY_PROFILE;
        if (eeprofile != null) {
            log.debug("Searching for End Entity Profile " + eeprofile);
            try {
                endentityprofileid = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileId(eeprofile);
            } catch (EndEntityProfileNotFoundException e) {
                errorString.append("End Entity Profile '" + eeprofile + "' does not exist.\n");
            }
        }

        int certificateprofileid = CertificateProfileConstants.CERTPROFILE_FIXED_ENDUSER;
        if (certificateprofile != null) {
            log.debug("Searching for Certificate Profile " + certificateprofile);
            certificateprofileid = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileId(
                    certificateprofile);
            if (certificateprofileid == CertificateProfileConstants.CERTPROFILE_NO_PROFILE) {
                log.error("Certificate Profile " + certificateprofile + " does not exist.");
                errorString.append("Certificate Profile '" + certificateprofile + "' does not exist.\n");
            }
        }

        CAInfo cainfo = getCAInfo(getAuthenticationToken(), caname);
        if (cainfo == null) {
            log.error("CA with name " + caname + " does not exist.");
            errorString.append("CA with name '" + caname + "' does not exist.\n");
        }

        if (errorString.length() > 0) {
            log.error(errorString.toString());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        final int crlPartitionIndex = cainfo.determineCrlPartitionIndex(certificate);

        final Certificate cacert = cainfo.getCertificateChain().iterator().next();
        log.info("Trying to add user:");
        log.info("Username: " + username);
        log.info("Password (hashed only): " + password);
        log.info("Email: " + email);
        log.info("DN: " + CertTools.getSubjectDN(certificate));
        log.info("CA Name: " + caname);
        log.info("Certificate Profile: "
                + EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(certificateprofileid));
        log.info("End Entity Profile: "
                + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(endentityprofileid));
        if (crlPartitionIndex != CertificateConstants.NO_CRL_PARTITION) {
            log.info("CRL Partition Index: " + crlPartitionIndex);
        }

        String subjectAltName = CertTools.getSubjectAlternativeName(certificate);
        if (subjectAltName != null) {
            log.info("SubjectAltName: " + subjectAltName);
        }
        log.info("Type: " + endEntityType.getHexValue());

        log.debug("Loading/updating user " + username);
        EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
        try {
            if (userdata == null) {

                try {
                endEntityManagementSession.addUser(getAuthenticationToken(), username,
                        password, CertTools.getSubjectDN(certificate), subjectAltName, email, false, endentityprofileid, certificateprofileid,
                        endEntityType, SecConst.TOKEN_SOFT_BROWSERGEN, cainfo.getCAId());
                } catch (EndEntityExistsException e) {
                    log.error("End entity with username " + username + " already exists.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                } 
                try {
                    if (status == CertificateConstants.CERT_ACTIVE) {
                        endEntityManagementSession.setUserStatus(getAuthenticationToken(),
                                username, EndEntityConstants.STATUS_GENERATED);
                    } else {
                        endEntityManagementSession.setUserStatus(getAuthenticationToken(),
                                username, EndEntityConstants.STATUS_REVOKED);
                    }
                } catch (NoSuchEndEntityException e) {
                    throw new IllegalStateException("Newly added end entity could not be located", e);
                }

                log.info("End Entity '" + username + "' has been added.");
            } else {
                EndEntityInformation endEntityInformation = new EndEntityInformation(username, CertTools.getSubjectDN(certificate), cainfo.getCAId(),
                        subjectAltName, email, (status == CertificateConstants.CERT_ACTIVE ? EndEntityConstants.STATUS_GENERATED
                                : EndEntityConstants.STATUS_REVOKED), endEntityType, endentityprofileid, certificateprofileid, null, null,
                        SecConst.TOKEN_SOFT_BROWSERGEN, null);
                endEntityInformation.setPassword(password);
                try {
                    endEntityManagementSession.changeUser(getAuthenticationToken(), endEntityInformation, false);
                } catch (NoSuchEndEntityException e) {
                    log.error("No such end entity.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }

                log.info("User '" + username + "' has been updated.");
            }
        } catch (CADoesntExistsException e) {
            log.error("No such CA " + caname);
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to create end entity.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (EndEntityProfileValidationException e) {
            log.error("User doesn't fulfill End Entity Profile ");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (WaitingForApprovalException e) {
            log.error("Approval is required to add End Entity.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CertificateSerialNumberException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IllegalNameException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (ApprovalException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CustomFieldException e) {
            log.error(e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        int certificateType = CertificateConstants.CERTTYPE_ENDENTITY;
        try {
            EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class).storeCertificateRemote(getAuthenticationToken(), EJBTools.wrap(certificate),
                    username, CertTools.getFingerprintAsString(cacert), CertificateConstants.CERT_ACTIVE, certificateType, certificateprofileid, endentityprofileid,
                    crlPartitionIndex, null, new Date().getTime());
            if (status == CertificateConstants.CERT_REVOKED) {
                try {
                    endEntityManagementSession.revokeCert(getAuthenticationToken(), CertTools.getSerialNumber(certificate), revocationTime, CertTools.getIssuerDN(certificate),
                            revocationReason.getDatabaseValue(), false);
                } catch (ApprovalException e) {
                    log.error(e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (AlreadyRevokedException e) {
                    log.error(e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (RevokeBackDateNotAllowedForProfileException e) {
                    log.error(e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (NoSuchEndEntityException e) {
                    log.error(e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                } catch (WaitingForApprovalException e) {
                    log.error(e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
        } catch (AuthorizationDeniedException e) {
            log.error("CLI user not authorized to import certificate.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }

        log.info("Certificate number '" + CertTools.getSerialNumberAsString(certificate) + "' has been added.");
        return CommandResult.SUCCESS;
    }

    /**
     * 
     * @param filename path to a file containing a PEM encoded certificate
     * @return the certificate
     * 
     * @throws IOException if the file didn't contain the certificate keys.
     * @throws CertificateException if the read PEM couldn't be decoded to a certificate
     * @throws FileNotFoundException if file wasn't found
     */
    private Certificate loadcert(String filename) throws IOException, CertificateException {
        File certfile = new File(filename);
        if (!certfile.exists()) {
            throw new FileNotFoundException(filename + " is not a file.");
        }

        byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(filename), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        Certificate cert = CertTools.getCertfromByteArray(bytes, Certificate.class);
        return cert;

    }

    @Override
    public String getCommandDescription() {
        return "Imports a certificate file to the database";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        sb.append("If E-mail isn't set (" + E_MAIL_KEY + "), the value from the certificate will be tried.\n\n");
        String existingCas = "";

        Collection<Integer> cas = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getAuthorizedCaIds(getAuthenticationToken());
        try {
            for (int caid : cas) {
                CAInfo info = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caid);
                existingCas += (existingCas.length() == 0 ? "" : ", ") + "\"" + info.getName() + "\"";
            }
        } catch (AuthorizationDeniedException e) {
            existingCas = "ERROR: CLI user not authorized to fetch available CAs>";
        }
        sb.append("Existing CAs: " + existingCas + "\n");
        String endEntityProfiles = "";
        Collection<Integer> eps = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getAuthorizedEndEntityProfileIds(
                getAuthenticationToken(), AccessRulesConstants.CREATE_END_ENTITY);
        for (int epid : eps) {
            endEntityProfiles += (endEntityProfiles.length() == 0 ? "" : ", ") + "\""
                    + EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class).getEndEntityProfileName(epid) + "\"";
        }
        sb.append("End entity profiles: " + endEntityProfiles + "\n");
        String certificateProfiles = "";
        Collection<Integer> cps = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class)
                .getAuthorizedCertificateProfileIds(getAuthenticationToken(), CertificateConstants.CERTTYPE_ENDENTITY);
        for (int cpid : cps) {
            certificateProfiles += (certificateProfiles.length() == 0 ? "" : ", ") + "\""
                    + EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateProfileSessionRemote.class).getCertificateProfileName(cpid) + "\"";
        }
        sb.append("Certificate profiles: " + certificateProfiles + "\n\n");
        sb.append("If an End entity profile is selected it must allow selected Certificate profiles.\n");
        sb.append("Valid Revocation reasons: ");
        RevocationReasons[] values = RevocationReasons.values();
        for(int i = 0; i < values.length; ++i) {
            if(!values[i].equals(RevocationReasons.NOT_REVOKED)) {
                sb.append(values[i].getStringValue());
                if(i < values.length -1) {
                    sb.append(" | ");
                }
            }
        }
        
        return sb.toString();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
