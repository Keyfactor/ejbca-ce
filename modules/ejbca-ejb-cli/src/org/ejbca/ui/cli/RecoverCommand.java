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

package org.ejbca.ui.cli;

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
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.log.LogLineParser;
import org.ejbca.core.ejb.ra.EndEntityExistsException;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.NoSuchEndEntityException;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.ra.CustomFieldException;
import org.ejbca.core.model.ra.raadmin.EndEntityProfileValidationException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.Base64;
import com.keyfactor.util.CertTools;
import com.keyfactor.util.EJBTools;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Recovers certificates and end entities from a log file created by the application server.
 */
public class RecoverCommand extends EjbcaCliUserCommandBase {
    private static final String LOG_FILE_KEY = "--log-file";
    private static final String IGNORE_ERRORS_KEY = "--ignore-errors";
    private static final String EXECUTE_KEY = "--execute";
    private static final String DELTA_KEY = "--delta";
    
    private static final int RECOVERY_STATUS_SKIPPED = 1; 
    private static final int RECOVERY_STATUS_SUCCESSFUL = 2;
    private static final int RECOVERY_STATUS_FAILED = 3;
    
    private final Map<Integer, String> caFingerprintCache = new HashMap<>();
    private boolean ignoreErrors = false;

    {
        registerParameter(new Parameter(LOG_FILE_KEY,
                "Log file",
                MandatoryMode.MANDATORY,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Path to a log file created by the application server."));
        registerParameter(new Parameter(IGNORE_ERRORS_KEY,
                "Ignore error",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.FLAG,
                "Continue to process input after a parsing error has occurred."));
        registerParameter(new Parameter(EXECUTE_KEY,
                "Execute the recover command",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.FLAG,
                "Confirm that the recovery command should be executed, potentially importing records into the database. Without the flag, information about what would be imported will be printed, but nothing will be recovered."));
        registerParameter(new Parameter(DELTA_KEY,
                "Execute the delta command",
                MandatoryMode.OPTIONAL,
                StandaloneMode.FORBID,
                ParameterMode.FLAG,
                "Compares delta in between persisted entries with logged creations"));
    }

    @Override
    public String getMainCommand() {
        return "recover";
    }

    @Override
    public String getCommandDescription() {
        return "Recover certificates and end entities.";
    }

    @Override
    public String getFullHelpText() {
        return "Recover end entities and certificates based on 'RA_ADDENDENTITY' and 'CERT_CREATION' audit log events. This can be useful if you have lost " +
                "data after restoring a backup. The certificates will be imported as active, and you must manually " +
                "import the latest CRL for a CA to update the revocation status in the database." +
                "Recovered entries will be logged in the audit log with 'RA_ADDENDENTITY' and 'CERT_STORED' entries." +
                "\nNOTE: Not all information from the original CertificateData table will be imported." +
                "\nNOTE: This command should be run on a test environment before recovering in production, hence the need to explicitly add the --execute flag.";
    }

    @Override
    protected Logger getLogger() {
        return Logger.getLogger(RecoverCommand.class);
    }

    @Override
    public CommandResult execute(final ParameterContainer parameters) {
        this.ignoreErrors = parameters.containsKey(IGNORE_ERRORS_KEY);
        final boolean executeFlag = parameters.containsKey(EXECUTE_KEY);
        final boolean deltaFlag = parameters.containsKey(DELTA_KEY);
        int numberOfCertificatesRecovered = 0;
        int numberOfCertificatesNotRecovered = 0;
        int numberOfCertificatesSkipped = 0;
        int numberOfEndEntitiesRecovered = 0;
        int numberOfEndEntitiesNotRecovered = 0;
        int numberOfEndEntitiesSkipped = 0;
        long lineNumber = 0;
        if (!executeFlag) {
            getLogger().info("Execute flag not provided, the following entries will be imported if execute flag is provided:");
        }
        try (BufferedReader bufferedReader = new BufferedReader(new FileReader(parameters.get(LOG_FILE_KEY)))) {
            for (String line; (line = bufferedReader.readLine()) != null;) {
                if (endEntityWasCreated(line)) {
                    int status = recoverEndEntity(executeFlag, deltaFlag, line, lineNumber);
                    if (status == RECOVERY_STATUS_SUCCESSFUL) {
                        numberOfEndEntitiesRecovered++;
                    } else if (status == RECOVERY_STATUS_SKIPPED) {
                        numberOfEndEntitiesSkipped++;
                    } else {
                        numberOfEndEntitiesNotRecovered++;                        
                    }
                } else if (certificateWasCreated(line)) {
                    final int status = recoverCertificate(executeFlag, deltaFlag, line, lineNumber);
                    if (status == RECOVERY_STATUS_SUCCESSFUL) {
                        numberOfCertificatesRecovered++;
                    } else if (status == RECOVERY_STATUS_SKIPPED) {
                        numberOfCertificatesSkipped++;
                    } else {
                        numberOfCertificatesNotRecovered++;
                    }
                }
                ++lineNumber;
            }
            if (executeFlag) {
                if (numberOfEndEntitiesRecovered == 0 && numberOfEndEntitiesSkipped == 0) {
                    getLogger().info("No end entities were recovered. Does the log contain any 'RA_ADDENDENTITY' audit log events?");
                } else {
                    getLogger().info("Recovered " + numberOfEndEntitiesRecovered + " end entities.");
                }
                if (numberOfCertificatesRecovered == 0 && numberOfCertificatesSkipped == 0) {
                    getLogger().info("No certificates were recovered. Does the log contain any 'CERT_CREATION' audit log events?");
                } else {
                    getLogger().info("Recovered " + numberOfCertificatesRecovered + " certificates.");
                }
                if (numberOfEndEntitiesNotRecovered > 0) {
                    getLogger().warn("Failed to recover " + numberOfEndEntitiesNotRecovered + " end entities.");
                }
                if (numberOfCertificatesNotRecovered > 0) {
                    getLogger().warn("Failed to recover " + numberOfCertificatesNotRecovered + " certificates.");
                }
                if (numberOfEndEntitiesSkipped > 0) {
                    getLogger().info("Skipped " + numberOfEndEntitiesSkipped + " end entities (already existing in database).");
                }
                if (numberOfCertificatesSkipped > 0) {
                    getLogger().info("Skipped " + numberOfCertificatesSkipped + " certificates (already existing in database).");
                }
            }
            return CommandResult.SUCCESS;
        } catch (final IOException e) {
            getLogger().error(e);
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CADoesntExistsException e) {
            getLogger().error(e);
            getLogger().error("A CA seems to be missing. Manually import the CA certificate before continuing.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (EndEntityProfileValidationException e) {
            getLogger().error(e);
            getLogger().error("End entity information could not be validated against the end entity profile. " +
                    "You may temporarily disable end entity profile limitations in the System Configuration to" +
                    "work around the issue.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (WaitingForApprovalException e) {
            getLogger().error(e);
            getLogger().error("A CA seem to have an approvals activated for adding/editing end entities. This is" +
                    "not supported when running this command. Disable approvals before continuing.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (final AuthorizationDeniedException e) {
            getLogger().error(e);
            return CommandResult.AUTHORIZATION_FAILURE;
        }
    }

    /**
     * <p>Recovers a certificate from a 'CERT_CREATION' audit log event. The recovered certificate is stored in
     * the database.
     *
     * <p>Example of what the audit log event looks like in the log (split on multiple lines and edited for readability):
     * <pre>
     * 2020-09-22 14:49:22,928 INFO  [org.cesecore.audit.impl.log4j.Log4jDevice] (default task-2) ⏎
     * 2020-09-22 14:49:22+02:00;CERT_CREATION;SUCCESS;CERTIFICATE;CORE;ADMIN_SUBJECT_DN;CA_ID;SERIAL_NO;⏎
     * EE_USERNAME;subjectdn=CERT_SUBJECT_DN;certprofile=CERT_PROFILE_ID;issuancerevocationreason=-1;cert=BASE64_CERT
     * </pre>
     *
     * @param execute if false will only print on console the values that would be imported if flag was set to true 
     * @param delta ignore entries which already exists in database.
     * @param line the log line to process.
     * @param lineNumber the line number of the line currently being processed.
     * @return true if the certificate was recovered successfully.
     * @throws AuthorizationDeniedException if the CLI administrator is not authorised to store certificates.
     */
    private int recoverCertificate(boolean execute, boolean delta, final String line, final long lineNumber) throws AuthorizationDeniedException, CADoesntExistsException {
        try {
            final CertificateStoreSessionRemote certificateStoreSession = EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class);
            final Certificate certificate = new LogLineParser(line).extractDataFromCaptureGroup(";cert=(.+)").getCertificateFromBase64Data();
            final String endEntityUsername = new LogLineParser(line).extractDataFromCaptureGroup(";([^;]+);subjectdn=").getString();
            final String caFingerprint = getCaFingerprintFromCaId(new LogLineParser(line).extractDataFromCaptureGroup(";(-?\\d+);.*;.*;subjectdn=").getInteger());
            final String certificateFingerprint = CertTools.getFingerprintAsString(certificate);
            final int certificateProfileId = new LogLineParser(line).extractDataFromCaptureGroup(";certprofile=(-?\\d+);").getInteger();
            if (!execute) {
                if (delta && certificateStoreSession.findCertificateByFingerprintRemote(certificateFingerprint) != null) {
                    return RECOVERY_STATUS_SKIPPED;
                }
                getLogger().info("\nEntry type: Certificate");
                getLogger().info("  Fingerprint: " + certificateFingerprint);
                getLogger().info("  CA fingerprint: " + caFingerprint);
                getLogger().info("  End entity username: " + endEntityUsername);
                getLogger().info("  Certificate profile ID: " + certificateProfileId);
                return RECOVERY_STATUS_SUCCESSFUL;
            }
            if (certificateStoreSession.findCertificateByFingerprintRemote(certificateFingerprint) != null) {
                getLogger().debug("Certificate with fingerprint " + certificateFingerprint + " already exists in the database.");
                return RECOVERY_STATUS_SKIPPED;
            }
            certificateStoreSession.storeCertificateRemote(
                    getAuthenticationToken(),
                    EJBTools.wrap(certificate),
                    endEntityUsername,
                    caFingerprint,
                    CertificateConstants.CERT_ACTIVE,
                    CertificateConstants.CERTTYPE_ENDENTITY,
                    certificateProfileId,
                    EndEntityConstants.EMPTY_END_ENTITY_PROFILE,
                    CertificateConstants.NO_CRL_PARTITION,
                    "",
                    System.currentTimeMillis(),
                    null); // accountBindingId
            return RECOVERY_STATUS_SUCCESSFUL;
        } catch (IllegalArgumentException e) {
            getLogger().error(e);
            getLogger().error("Unable to recover certificate on line " + lineNumber + ".");
            if (ignoreErrors) {
                return RECOVERY_STATUS_FAILED;
            } else {
                throw e;
            }
        }
    }

    private String getCaFingerprintFromCaId(final int caId) throws AuthorizationDeniedException, CADoesntExistsException {
        if (caFingerprintCache.containsKey(caId)) {
            return caFingerprintCache.get(caId);
        }
        final CAInfo caInfo = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caId);
        if (caInfo == null) {
            throw new CADoesntExistsException("The CA with CA ID " + caId + " does not exist.");
        }
        final List<Certificate> certificateChain = caInfo.getCertificateChain();
        if (certificateChain.size() == 0) {
            throw new CADoesntExistsException("The CA with CA ID " + caId + " does not have a certificate chain.");
        }
        final String caFingerprint = CertTools.getFingerprintAsString(certificateChain.get(0));
        caFingerprintCache.put(caId, caFingerprint);
        return caFingerprint;
    }

    /**
     * <p>Recovers an end entity from a 'RA_ADDENDENTITY' audit log event. The recovered end entity is stored in the database.
     *
     * <p>Example of what the audit log event looks like in the log (split on multiple lines and edited for readability):
     * <pre>
     * 2020-09-22 14:49:22,685 INFO  [org.cesecore.audit.impl.log4j.Log4jDevice] (default task-2) ⏎
     * 2020-09-22 14:49:22+02:00;RA_ADDENDENTITY;SUCCESS;RA;CORE;ADMIN_SUBJECT_DN;CA_ID;;EE_USERNAME;⏎
     * msg=Added end entity EE_USERNAME.;caid=CA_ID;cardnumber=;certificateprofileid=CERT_PROFILE_ID;⏎
     * endentityprofileid=EE_PROFILE_ID;extendedInformation= [version:4.0], [type:0], [subjectdirattributes:], ⏎
     * [maxfailedloginattempts:-1], [remainingloginattempts:-1], [KEYSTORE_ALGORITHM_TYPE:RSA], ⏎
     * [KEYSTORE_ALGORITHM_SUBTYPE:2048]};status=10;subjectAltName=B64:SUBJECT_DN;subjectDN=B64:SUBJECT_DN;⏎
     * subjectEmail=;timecreated=Tue Sep 22 14:49:22 CEST 2020;timemodified=Tue Sep 22 14:49:22 CEST 2020;⏎
     * tokentype=2;type=129;username=EE_USERNAME
     * </pre>
     *
     * @param execute if false will only print on console the values that would be imported if flag was set to true 
     * @param delta ignore entries which already exists in database.
     * @param line the log line to process.
     * @param lineNumber the line number of the line currently being processed.
     * @return true if the end entity was recovered successfully.
     * @throws AuthorizationDeniedException if the CLI administrator is not authorised to create or edit end entities.
     * @throws CADoesntExistsException if the CA of the end entity does not exist.
     * @throws EndEntityProfileValidationException if the end entity information cannot be validated against the end
     * entity profile.
     * @throws WaitingForApprovalException if the CA requires approval for editing/adding end entities
     */
    private int recoverEndEntity(boolean execute, boolean delta, final String line, final long lineNumber) throws AuthorizationDeniedException,
            CADoesntExistsException, EndEntityProfileValidationException, WaitingForApprovalException {
        try {
            final EndEntityManagementSessionRemote endEntityManagementSession = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class);
            final String endEntityUsername = new LogLineParser(line).extractDataFromCaptureGroup(";username=(.+)").getString();
            final String subjectDn = new LogLineParser(line).extractDataFromCaptureGroup("=;subjectDN=B64:(.+);subjectEmail").base64Decode().getString();
            int endEntityProfileId;
            try {
                endEntityProfileId = new LogLineParser(line).extractDataFromCaptureGroup(";endentityprofileid=(-?\\d+);extendedInformation").getInteger();
            } catch (IllegalArgumentException e) {
                // ExtendedInformation may be null
                endEntityProfileId = new LogLineParser(line).extractDataFromCaptureGroup(";endentityprofileid=(-?\\d+);status").getInteger();
            }
            final int certificateProfileId = new LogLineParser(line).extractDataFromCaptureGroup(";certificateprofileid=(-?\\d+);endentityprofileid").getInteger();
            final int tokenType = new LogLineParser(line).extractDataFromCaptureGroup(";tokentype=(-?\\d+);type").getInteger();
            final int caId = new LogLineParser(line).extractDataFromCaptureGroup(";caid=(-?\\d+);cardnumber=").getInteger();
            final Optional<String> subjectAltName = new LogLineParser(line).extractDataFromCaptureGroup(";subjectAltName=B64:(.+);subjectDN").getOptionalString();
            final EndEntityInformation endEntityInformation = new EndEntityInformation();
            endEntityInformation.setUsername(endEntityUsername);
            endEntityInformation.setDN(subjectDn);
            endEntityInformation.setPassword("foo123");
            endEntityInformation.setStatus(EndEntityConstants.STATUS_GENERATED);
            final EndEntityType endEntityType = new EndEntityType();
            endEntityType.addType(EndEntityTypes.ENDUSER);
            endEntityInformation.setType(endEntityType);
            endEntityInformation.setCertificateProfileId(certificateProfileId);
            endEntityInformation.setEndEntityProfileId(endEntityProfileId);
            endEntityInformation.setTokenType(tokenType);
            endEntityInformation.setCAId(caId);
            if (subjectAltName.isPresent()) {
                endEntityInformation.setSubjectAltName(new String(Base64.decode(subjectAltName.get().getBytes(StandardCharsets.US_ASCII))));
            }
            if (!execute) {
                if (delta && endEntityManagementSession.existsUser(endEntityUsername)) {
                    return RECOVERY_STATUS_SKIPPED;
                }
                getLogger().info("\nEntry type: End Entity");
                getLogger().info("  Username: " + endEntityInformation.getUsername());
                getLogger().info("  Subject DN: " + endEntityInformation.getDN());
                getLogger().info("  Subject altName: " + endEntityInformation.getSubjectAltName());
                getLogger().info("  End entity profile ID: " + endEntityInformation.getEndEntityProfileId());
                getLogger().info("  Certificate profile ID: " + endEntityInformation.getCertificateProfileId());
                getLogger().info("  CA ID: " + endEntityInformation.getCAId());
                return RECOVERY_STATUS_SUCCESSFUL;
            }

            if (endEntityManagementSession.existsUser(endEntityUsername)) {
                if (delta) {
                    return RECOVERY_STATUS_SKIPPED;
                }
                endEntityManagementSession.changeUser(getAuthenticationToken(), endEntityInformation, false);
            } else {
                endEntityManagementSession.addUser(getAuthenticationToken(), endEntityInformation, false);
            }
            return RECOVERY_STATUS_SUCCESSFUL;
        } catch (IllegalNameException |
                 NoSuchEndEntityException |
                 EndEntityExistsException |
                 ApprovalException |
                 CustomFieldException |
                 CertificateSerialNumberException |
                 IllegalArgumentException e) {
            getLogger().error("Unable to recover end entity on line " + lineNumber + ".");
            if (ignoreErrors) {
                return RECOVERY_STATUS_FAILED;
            } else {
                throw new RuntimeException(e);
            }
        }
    }

    private boolean certificateWasCreated(final String line) {
        return StringUtils.contains(line, "CERT_CREATION;SUCCESS");
    }

    private boolean endEntityWasCreated(final String line) {
        return StringUtils.contains(line, "RA_ADDENDENTITY;SUCCESS");
    }
}
