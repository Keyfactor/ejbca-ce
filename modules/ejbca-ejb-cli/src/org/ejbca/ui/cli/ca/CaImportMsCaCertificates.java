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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.MalformedInputException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.certificate.CertificateStoreSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.SimpleTime;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CertTools;

/**
 * Implementation of the CLI command <code>./ejbca.sh ca importcertsms</code>.
 * 
 * <p>This command is used to migrate data exported from a Microsoft CA-installation using the <code>certutil</code>
 * tool in Windows to EJBCA.
 * 
 * @version $Id$
 */
public class CaImportMsCaCertificates extends BaseCaAdminCommand {
    /**
     * Represents the result of a single import operation.
     */
    private static class ImportResult {
        private Status status;
        private String message;

        public enum Status {
            PROCESSED, ERROR, SKIPPED,
        }

        public static ImportResult fromCliResult(final CommandResult commandResult, final String username) {
            final ImportResult importResult = new ImportResult();
            if (commandResult == CommandResult.SUCCESS) {
                importResult.status = Status.PROCESSED;
                importResult.message = "Imported row #%d for end entity '" + username + "'.";
            } else {
                importResult.status = Status.ERROR;
                importResult.message = "Import of row #%d failed with error " + commandResult.name() + ". See previous log output for details.";
            }
            return importResult;
        }

        public static ImportResult skipped(final X509Certificate certificate) {
            final ImportResult importResult = new ImportResult();
            importResult.status = Status.SKIPPED;
            importResult.message = "Skipped row %d, certificate with fingerprint " + CertTools.getFingerprintAsString(certificate)
                    + " already exists in the database.";
            return importResult;
        }

        public static ImportResult empty() {
            final ImportResult importResult = new ImportResult();
            importResult.status = Status.SKIPPED;
            importResult.message = "Skipped row #%d, the certificate was never issued.";
            return importResult;
        }

        public Status getStatus() {
            return status;
        }

        public String getMessage(final int rowNumber) {
            return String.format(message, rowNumber);
        }
    }

    /**
     * Represents possible values for the 'Request Disposition' field.
     */
    private enum RequestDisposition {
        ISSUED, REVOKED, DENIED, PENDING, UNKNOWN;

        public static RequestDisposition parse(final String data) throws IOException {
            final String[] parts = data.split("--");
            if (parts.length != 2) {
                throw new IOException(
                        "Expected [ 'Request Disposition: <CODE_HEX> (<CODE_DEC>)', <NAME> ], but parsed " + Arrays.asList(parts) + ".");
            }
            try {
                return RequestDisposition.valueOf(StringUtils.trim(parts[1]).toUpperCase());
            } catch (final IllegalArgumentException e) {
                return UNKNOWN;
            }
        }
    }

    private static final String CA_NAME_KEY = "--caname";
    private static final String INPUT_FILE = "-f";
    private static final String EE_USERNAME = "--ee-username";
    private static final String EE_PASSWORD = "--ee-password";
    private static final String CHARSET_KEY = "--charset";

    {
        registerParameter(new Parameter(INPUT_FILE, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Path to a dump file created by certutil. You can create a dump with the appropriate data using the following command in Windows:"
                        + System.lineSeparator() + System.lineSeparator() + "    certutil -view -restrict \"GeneralFlags > 0\" /out \\"
                        + System.lineSeparator() + "        \"UPN,CertificateTemplate,Disposition,RawCertificate\" > certdump.txt"
                        + System.lineSeparator()));
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The name of an existing CA in EJBCA, whose certificates are going to be imported."));
        registerParameter(new Parameter(EE_USERNAME, "End Entity Username", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Specify a single field, or a comma-separated list of fields in the certificate from where the end entity username is extracted. Possible values are:" 
                    + System.lineSeparator() + System.lineSeparator() 
                    + "    SERIAL_NUMBER - Use the certificate serial number" + System.lineSeparator()
                    + "    SERIAL_NUMBER_HEX - Use the certificate serial number in hexadecimal format" + System.lineSeparator()
                    + "    DN - Use the whole subject distinguished name" + System.lineSeparator()
                    + "    CN - Use the first common name in the subject distinguished name" + System.lineSeparator()
                    + "    O - Use the first organization in the subject distinguished name" + System.lineSeparator()
                    + "    OU - Use the first organizational unit in the subject distinguished name" + System.lineSeparator()
                    + "    UPN - Use a non-empty Microsoft UPN from the certutil dump file" + System.lineSeparator()
                    + "    universalPrincipalName - Use the first Microsoft UPN in the subject alternative name"
                    + System.lineSeparator() + System.lineSeparator() + 
                    "If multiple fields are specified, the first non-empty one is used. If the certificate does not contain any of " + 
                    "the specified fields, the certificate serial number is used instead."));
        registerParameter(new Parameter(EE_PASSWORD, "End Entity Password", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The password (enrollment code) to use for new end entities. If no password is specified, the default password 'foo123' is used."));
        registerParameter(new Parameter(CHARSET_KEY, "File encoding", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The file encoding of the certutil dump file. Using UTF-16 if omitted."));
    }

    @Override
    public String getMainCommand() {
        return "importcertsms";
    }

    @Override
    public String getCommandDescription() {
        return "Import certificates and metadata from a Microsoft CA-installation.";
    }

    @Override
    public String getFullHelpText() {
        return getCommandDescription() + System.lineSeparator() + System.lineSeparator()
                + "This command helps you to migrate certificates, revocation information and end entities from an existing Microsoft CA-installation to EJBCA."
                + System.lineSeparator() + System.lineSeparator()
                + "Before starting the migration, you need to create the appropriate profiles and the CA to use during the import. Then export the existing data "
                + "in your Microsoft CA-installation to a dump file. Use the certutil tool in Windows for this task:" + System.lineSeparator()
                + System.lineSeparator() + "    certutil -view -restrict \"GeneralFlags > 0\" /out \\" + System.lineSeparator()
                + "        \"UPN,CertificateTemplate,Disposition,RawCertificate\" > certdump.txt" + System.lineSeparator() + System.lineSeparator()
                + "This command creates a file 'certdump.txt' containing, for each certificate, the User Principal Name (UPN) of the user to whom the certificate "
                + "was issued, the OID and name of the certificate template used, the revocation status and the actual PEM encoded certificate."
                + System.lineSeparator() + System.lineSeparator()
                + "Once the dump file has been created, it can be imported to EJBCA using the 'importcertsms' command. For example:"
                + System.lineSeparator() + System.lineSeparator() + "    ./ejbca.sh ca importcertsms '/path/to/certdump.txt' 'Name of CA'"
                + System.lineSeparator() + System.lineSeparator()
                + "During the import, an end entity is created in EJBCA if one does not already exist. The serial number of the certificate is used as the "
                + "username of the end entity by default. If desired, the username can be derived from a field in the certificate instead, by using the "
                + "--ee-username argument." + System.lineSeparator() + System.lineSeparator()
                + "The certificate is evaluated against the certificate profile and end entity profile with names corresponding to the 'Certificate Template' "
                + "specified in the dump file." + System.lineSeparator() + System.lineSeparator()
                + "Once the certificate has been imported successfully to EJBCA's database, its revocation status is set. Revoked certificates will appear on the "
                + "next CRL issued by the CA." + System.lineSeparator() + System.lineSeparator()
                + "If an error is encountered during import (e.g. missing certificate or end entity profile, corrupt certificate or violation of an end entity "
                + "constraint), the import terminates with an error message. Once the problem has been fixed, you can run the 'importcertsms' command again. "
                + "Already imported certificates are skipped and the command resumes to import the remaining certificates.";
    }

    @Override
    protected Logger getLogger() {
        return Logger.getLogger(CaImportMsCaCertificates.class);
    }

    @Override
    public CommandResult execute(final ParameterContainer parameters) {
        try (final BufferedReader reader = Files.newBufferedReader(Paths.get(parameters.get(INPUT_FILE)), getCharset(parameters.get(CHARSET_KEY)))) {
            int processedCount = 0;
            int skippedCount = 0;
            final long startTime = System.currentTimeMillis();
            for (String line; (line = reader.readLine()) != null; ) {
                if (StringUtils.startsWith(line, "Row")) {
                    final int rowNumber = getRowNumber(line);
                    final ImportResult importResult = importEntry(parameters, reader, rowNumber);
                    if (importResult.getStatus() == ImportResult.Status.ERROR) {
                        getLogger().error(importResult.getMessage(rowNumber));
                        return CommandResult.FUNCTIONAL_FAILURE;
                    }
                    getLogger().info(importResult.getMessage(rowNumber));
                    if (importResult.getStatus() == ImportResult.Status.PROCESSED) {
                        processedCount++;
                    } else {
                        skippedCount++;
                    }
                } else {
                    getLogger().trace("Skipping line '" + line + "'.");
                }
            }
            final long duration = System.currentTimeMillis() - startTime;
            getLogger().info("------------------------------------------------------------------------------");
            getLogger().info("|                                                                             |");
            getLogger().info("|                             =: S U M M A R Y :=                             |");
            getLogger().info("|                                                                             |");
            getLogger().info("-------------------------------------------------------------------------------");
            getLogger().info("");
            if (processedCount > 0) {
                getLogger().info("All rows imported successfully. Enjoy!");
                getLogger().info("");
                if (duration / 1000 == 0) {
                    getLogger().info("Processed " + processedCount + " certificates in " + duration + " ms.");
                } else {
                    getLogger().info("Processed " + processedCount + " certificates in " + SimpleTime.getInstance(duration).toString() + " ("
                            + (processedCount / (duration / 1000)) + " certificates / second).");
                }
            } else {
                getLogger().info("No rows were imported.");
            }
            if (skippedCount > 0) {
                getLogger().info("");
                getLogger().info(skippedCount + " certificates were missing in the dump file, or already present");
                getLogger().info("in the database, and were skipped.");
            }
            getLogger().info("");
            getLogger().info("-------------------------------------------------------------------------------");
            return CommandResult.SUCCESS;
        } catch (final IllegalArgumentException e) {
            getLogger().error(e.getMessage());
            return CommandResult.CLI_FAILURE;
        } catch (final FileNotFoundException e) {
            getLogger().error(String.format("The file '%s' does not exist or cannot be read.", parameters.get(INPUT_FILE)));
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (MalformedInputException e) {
            getLogger().error("A problem occurred when reading the certutil dump file. Are you using the correct charset? Problem description: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (final IOException e) {
            getLogger().error("The certutil dump file could not be parsed. Problem description: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (final CertificateParsingException e) {
            getLogger().error("Unable to parse X.509 certificate: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    private Charset getCharset(final String charsetName) {
        if (charsetName == null) {
            // This is the default charset on Windows machines
            return StandardCharsets.UTF_16;
        }
        return Charset.forName(charsetName);
    }

    private int getRowNumber(final String line) throws IOException {
        try {
            final String rowNumber = StringUtils.remove(StringUtils.substringAfter(line, "Row "), ":");
            return Integer.parseInt(rowNumber);
        } catch (final NumberFormatException e) {
            throw new IOException("Cannot extract row number from line '" + line + "'.");
        }
    }

    private ImportResult importEntry(final ParameterContainer parameters, final BufferedReader reader, final int rowNumber)
            throws IOException, CertificateParsingException {
        final String upn = parseUpn(reader);
        final String certificateTemplate = parseCertificateTemplate(reader);
        final RequestDisposition requestDisposition = parseRequestDisposition(reader);

        if (requestDisposition == RequestDisposition.DENIED || requestDisposition == RequestDisposition.PENDING) {
            return ImportResult.empty();
        }

        final String pem = parseCertificateAsPem(reader);

        if (pem == null) {
            getLogger().warn("Row #" + rowNumber + " does not contain a certificate.");
            return ImportResult.empty();
        }

        final String pathToCertificate = writeCertificate(reader, pem);

        final X509Certificate certificate = CertTools.getCertfromByteArray(pem.getBytes(), X509Certificate.class);
        final String username = getEndEntityUsername(parameters, upn, certificate);
        final String password = getEndEntityPassword(parameters);

        if (certificateAlreadyExists(certificate)) {
            FileUtils.forceDelete(new File(pathToCertificate));
            return ImportResult.skipped(certificate);
        }

        final CommandResult commandResult = new CaImportCertCommand().execute(
                "--caname", parameters.get(CA_NAME_KEY), 
                "--password", password,
                "--username", username, 
                "-a", requestDisposition == RequestDisposition.REVOKED ? "REVOKED" : "ACTIVE",
                "-f", pathToCertificate, 
                "--certprofile", certificateTemplate,
                "--eeprofile", certificateTemplate,
                "--overwrite");
        FileUtils.forceDelete(new File(pathToCertificate));
        return ImportResult.fromCliResult(commandResult, username);
    }

    private boolean certificateAlreadyExists(final X509Certificate certificate) {
        return EjbRemoteHelper.INSTANCE.getRemoteSession(CertificateStoreSessionRemote.class)
                .findCertificateByFingerprintRemote(CertTools.getFingerprintAsString(certificate)) != null;
    }

    private String writeCertificate(final BufferedReader reader, final String pem) throws IOException {
        final File temporaryFile = File.createTempFile("certificate-", ".pem");
        try (final BufferedWriter writer = new BufferedWriter(new FileWriter(temporaryFile))) {
            writer.write(pem);
            return temporaryFile.getAbsolutePath();
        }
    }

    private String parseCertificateAsPem(final BufferedReader reader) throws IOException {
        final String propertyLine = parseProperty(reader, "Binary Certificate");
        if (propertyLine.endsWith("EMPTY")) {
            return null;
        }
        final String beginCertificate = reader.readLine();
        if (!StringUtils.equals(beginCertificate, CertTools.BEGIN_CERTIFICATE)) {
            throw new IOException("Expected BEGIN_CERTIFICATE but read '" + beginCertificate + "'.");
        }
        final StringBuilder pem = new StringBuilder();
        pem.append(beginCertificate);
        for (String nextLine; (nextLine = reader.readLine()) != null;) {
            pem.append("\n");
            pem.append(nextLine);
            if (StringUtils.equals(nextLine, CertTools.END_CERTIFICATE)) {
                return pem.toString();
            }
        }
        throw new IOException("Premature end of file while reading certificate. Missing or corrupted END_CERTIFICATE marker?");
    }

    private RequestDisposition parseRequestDisposition(final BufferedReader reader) throws IOException {
        final String line = parseProperty(reader, "Request Disposition");
        return RequestDisposition.parse(line);
    }

    private String parseCertificateTemplate(final BufferedReader reader) throws IOException {
        final String line = parseProperty(reader, "Certificate Template");
        final String lineWithoutProperty = StringUtils.removeStart(line, "Certificate Template:");
        final String[] parts = StringUtils.trim(lineWithoutProperty).split(" ");
        if (parts.length == 1) {
            // Format is either 'Certificate Template: "<OID>" or Certificate Template: "<NAME>"'
            return StringUtils.strip(parts[0], "\"");
        }
        if (parts.length == 2) {
            // Format is 'Certificate Template: "<OID>" "<NAME>"'
            return StringUtils.strip(parts[1], "\"");
        }
        throw new IOException("Certificate template could not be parsed. Expected [ '<OID>', '<TemplateName>' ] " +
                "or [ '<TemplateName>' ], but parsed " + Arrays.asList(parts) + ".");
    }

    private String parseUpn(final BufferedReader reader) throws IOException {
        final String line = parseProperty(reader, "User Principal Name");
        return StringUtils.strip(StringUtils.substringAfter(line, ":"));
    }

    private String parseProperty(final BufferedReader reader, final String property) throws IOException {
        final String line = StringUtils.strip(reader.readLine());
        if (line == null) {
            throw new IOException("Premature end of file while reading '" + property + "'.");
        }
        if (!line.startsWith(property)) {
            throw new IOException("Expected line starting with '" + property + "' but read '" + line + "'.");
        }
        return line;
    }

    private String getEndEntityUsername(final ParameterContainer parameters, final String upn, final X509Certificate certificate) {
        if (parameters.get(EE_USERNAME) == null) {
            return certificate.getSerialNumber().toString();
        }
        for (final String eeUsernameField : parameters.get(EE_USERNAME).split(",")) {
            if (StringUtils.equals(eeUsernameField, "SERIAL_NUMBER")) {
                return certificate.getSerialNumber().toString();
            }
            if (StringUtils.equals(eeUsernameField, "SERIAL_NUMBER_HEX")) {
                return certificate.getSerialNumber().toString(16);
            }
            if (StringUtils.equals(eeUsernameField, "DN")) {
                final String subjectDn = CertTools.getSubjectDN(certificate);
                if (StringUtils.isEmpty(subjectDn)) {
                    continue;
                }
                return subjectDn;
            }
            if (StringUtils.equals(eeUsernameField, "CN")) {
                final String subjectDn = CertTools.getSubjectDN(certificate);
                final String cn = CertTools.getPartFromDN(subjectDn, "CN");
                if (StringUtils.isEmpty(cn)) {
                    continue;
                }
                return cn;
            }
            if (StringUtils.equals(eeUsernameField, "O")) {
                final String subjectDn = CertTools.getSubjectDN(certificate);
                final String o = CertTools.getPartFromDN(subjectDn, "O");
                if (StringUtils.isEmpty(o)) {
                    continue;
                }
                return o;
            }
            if (StringUtils.equals(eeUsernameField, "OU")) {
                final String subjectDn = CertTools.getSubjectDN(certificate);
                final String ou = CertTools.getPartFromDN(subjectDn, "OU");
                if (StringUtils.isEmpty(ou)) {
                    continue;
                }
                return ou;
            }
            if (StringUtils.equals(eeUsernameField, "UPN")) {
                if (StringUtils.equals(upn, "EMPTY")) {
                    continue;
                }
                return upn;
            }
            if (StringUtils.equals(eeUsernameField, "universalPrincipalName")) {
                final String upnFromCertificate = CertTools.getPartFromDN(CertTools.getSubjectAlternativeName(certificate), CertTools.UPN);
                if (StringUtils.isEmpty(upnFromCertificate)) {
                    continue;
                }
                return upnFromCertificate;
            }
            throw new IllegalArgumentException("Cannot extract an end entity username from the unknown certificate field " + eeUsernameField + ".");
        }
        return certificate.getSerialNumber().toString();
    }

    private String getEndEntityPassword(final ParameterContainer parameters) {
        return !parameters.containsKey(EE_PASSWORD) ? "foo123" : parameters.get(EE_PASSWORD);
    }
}
