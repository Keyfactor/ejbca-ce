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

package org.ejbca.core.model.ca.publisher;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.cert.CRLException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.lang.SystemUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.x509.Extension;
import org.cesecore.authentication.tokens.AuthenticationToken;
import org.cesecore.certificates.certificate.CertificateConstants;
import org.cesecore.certificates.endentity.ExtendedInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.model.InternalEjbcaResources;

/**
 * This class is used for publishing to user defined script or command.
 * 
 * @version $Id$
 */
public class GeneralPurposeCustomPublisher implements ICustomPublisher, CustomPublisherUiSupport {
    private static Logger log = Logger.getLogger(GeneralPurposeCustomPublisher.class);
    private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();

    public static final String CRL_EXTERNAL_COMMAND_PROPERTY_NAME = "crl.application";
    public static final String CALCULATE_DELTA_CRL_LOCALLY_PROPERTY_NAME = "crl.calclulateDeltaCrlLocally";
    public static final String CERT_EXTERNAL_COMMAND_PROPERTY_NAME = "cert.application";
    public static final String REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME = "revoke.application";
    public static final String CRL_FAIL_ON_ERRORCODE_PROPERTY_NAME = "crl.failOnErrorCode";
    public static final String CERT_FAIL_ON_ERRORCODE_PROPERTY_NAME = "cert.failOnErrorCode";
    public static final String REVOKE_FAIL_ON_ERRORCODE_PROPERTY_NAME = "revoke.failOnErrorCode";
    public static final String CRL_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME = "crl.failOnStandardError";
    public static final String CERT_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME = "cert.failOnStandardError";
    public static final String REVOKE_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME = "revoke.failOnStandardError";

    private String crlExternalCommandFileName = null;
    private String certExternalCommandFileName = null;
    private String revokeExternalCommandFileName = null;
    private boolean calclulateDeltaCrlLocally = false;
    private boolean crlFailOnErrorCode = true;
    private boolean certFailOnErrorCode = true;
    private boolean revokeFailOnErrorCode = true;
    private boolean crlFailOnStandardError = true;
    private boolean certFailOnStandardError = true;
    private boolean revokeFailOnStandardError = true;

    /**
     * Creates a new instance of DummyCustomPublisher
     */
    public GeneralPurposeCustomPublisher() {
    }

    /**
     * Load used properties.
     * 
     * @param properties
     *            The properties to load.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#init(java.util.Properties)
     */
    @Override
    public void init(Properties properties) {
    	if (log.isTraceEnabled()) {
    		log.trace(">init");
    	}
        // Extract system properties
        crlFailOnErrorCode = properties.getProperty(CRL_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        crlFailOnStandardError = properties.getProperty(CRL_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        crlExternalCommandFileName = properties.getProperty(CRL_EXTERNAL_COMMAND_PROPERTY_NAME);
        certFailOnErrorCode = properties.getProperty(CERT_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        certFailOnStandardError = properties.getProperty(CERT_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        certExternalCommandFileName = properties.getProperty(CERT_EXTERNAL_COMMAND_PROPERTY_NAME);
        revokeFailOnErrorCode = properties.getProperty(REVOKE_FAIL_ON_ERRORCODE_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        revokeFailOnStandardError = properties.getProperty(REVOKE_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, "true").equalsIgnoreCase("true");
        revokeExternalCommandFileName = properties.getProperty(REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME);
        calclulateDeltaCrlLocally = properties.getProperty(CALCULATE_DELTA_CRL_LOCALLY_PROPERTY_NAME, "false").equalsIgnoreCase("true");
    } // init

    @Override
    public List<CustomPublisherProperty> getCustomUiPropertyList() {
        final List<CustomPublisherProperty> ret = new ArrayList<>();
        ret.add(new CustomPublisherProperty(CRL_FAIL_ON_ERRORCODE_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(crlFailOnErrorCode)));
        ret.add(new CustomPublisherProperty(CRL_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(crlFailOnStandardError)));
        ret.add(new CustomPublisherProperty(CRL_EXTERNAL_COMMAND_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, crlExternalCommandFileName));
        ret.add(new CustomPublisherProperty(CERT_FAIL_ON_ERRORCODE_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(certFailOnErrorCode)));
        ret.add(new CustomPublisherProperty(CERT_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(certFailOnStandardError)));
        ret.add(new CustomPublisherProperty(CERT_EXTERNAL_COMMAND_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, certExternalCommandFileName));
        ret.add(new CustomPublisherProperty(REVOKE_FAIL_ON_ERRORCODE_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(revokeFailOnErrorCode)));
        ret.add(new CustomPublisherProperty(REVOKE_FAIL_ON_STANDARD_ERROR_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(revokeFailOnStandardError)));
        ret.add(new CustomPublisherProperty(REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME, CustomPublisherProperty.UI_TEXTINPUT, revokeExternalCommandFileName));
        ret.add(new CustomPublisherProperty(CALCULATE_DELTA_CRL_LOCALLY_PROPERTY_NAME, CustomPublisherProperty.UI_BOOLEAN, String.valueOf(calclulateDeltaCrlLocally)));
        return ret;
    }

    /**
     * Writes certificate to temporary file and executes an external command with
     * the full pathname of the temporary file as argument. The temporary file
     * is the encoded form of the certificate e.g. X.509 certificates would be
     * encoded as ASN.1 DER. All parameters but incert are ignored.
     * 
     * @param incert
     *            The certificate
     * @param username
     *            The username
     * @param type
     *            The certificate type
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCertificate(org.ejbca.core.model.log.Admin,
     *      java.security.cert.Certificate, java.lang.String, java.lang.String,
     *      int, int)
     */
    @Override
    public boolean storeCertificate(AuthenticationToken admin, Certificate incert, String username, String password, String userDN, String cafp, int status, int type, long revocationDate,
            int revocationReason, String tag, int certificateProfileId, long lastUpdate, ExtendedInformation extendedinformation) throws PublisherException {
        if (log.isTraceEnabled()) {
            log.trace(">storeCertificate, Storing Certificate for user: " + username);
        }

        if (status == CertificateConstants.CERT_REVOKED) {
            // Call separate script for revocation
            revokeCertificate(admin, incert, revocationReason);
        } else if (status == CertificateConstants.CERT_ACTIVE) {
            // Don't publish non-active certificates
            // Make sure that an external command was specified
            if (certExternalCommandFileName == null) {
                String msg = intres.getLocalizedMessage("publisher.errormissingproperty", CERT_EXTERNAL_COMMAND_PROPERTY_NAME);
                log.error(msg);
                throw new PublisherException(msg);
            }
            // Run internal method to create tempfile and run the command
            List<String> arguments = new ArrayList<>();
            arguments.add(String.valueOf(type));
            try {
                arguments.add(CertTools.getSubjectDN(incert));
                arguments.add(CertTools.getIssuerDN(incert));
                arguments.add(CertTools.getSerialNumberAsString(incert));
                runWithTempFile(certExternalCommandFileName, incert.getEncoded(), certFailOnErrorCode, certFailOnStandardError, arguments);
            } catch (CertificateEncodingException e) {
                String msg = intres.getLocalizedMessage("publisher.errorcertconversion");
                log.error(msg);
                throw new PublisherException(msg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace("<storeCertificate");
        }
        return true;
    } // storeCertificate

    /**
     * Writes the CRL to a temporary file and executes an external command with
     * the temporary file as argument. By default, a PublisherException is
     * thrown if the external command returns with an errorlevel or outputs to
     * stderr.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#storeCRL(org.ejbca.core.model.log.Admin,
     *      byte[], java.lang.String, int)
     */
    @Override
    public boolean storeCRL(AuthenticationToken admin, byte[] incrl, String cafp, int number, String userDN) throws PublisherException {
        if (log.isTraceEnabled()) {
        	log.trace(">storeCRL, Storing CRL");
        }
        // Verify initialization
        if (crlExternalCommandFileName == null) {
            String msg = intres.getLocalizedMessage("publisher.errormissingproperty", CRL_EXTERNAL_COMMAND_PROPERTY_NAME);
            log.error(msg);
            throw new PublisherException(msg);
        }

        List<String> additionalArguments = new ArrayList<>();

        if (calclulateDeltaCrlLocally) {
            X509CRL crl;
            try {
                crl = CertTools.getCRLfromByteArray(incrl);
                additionalArguments.add(Boolean.toString(crl.getExtensionValue(Extension.deltaCRLIndicator.getId()) != null));
            } catch (CRLException e) {
                log.error("Byte array does not contain a correct CRL.", e);
            }

        }

        // Run internal method to create tempfile and run the command
        runWithTempFile(crlExternalCommandFileName, incrl, crlFailOnErrorCode, crlFailOnStandardError, additionalArguments);
        if (log.isTraceEnabled()) {
        	log.trace("<storeCRL");
        }
        return true;
    }

    /**
     * Writes certificate to temporary file and executes an external command
     * with the full pathname of the temporary file as argument. The temporary
     * file is the encoded form of the certificate e.g. X.509 certificates would
     * be encoded as ASN.1 DER. All parameters but cert are ignored.
     * 
     * @param cert
     *            The certificate
     * 
     */
    public void revokeCertificate(AuthenticationToken admin, Certificate cert, int reason) throws PublisherException {
        if (log.isTraceEnabled()) {
        	log.trace(">revokeCertificate, Rekoving Certificate");
        }
        // Verify initialization
        if (revokeExternalCommandFileName == null) {
            String msg = intres.getLocalizedMessage("publisher.errormissingproperty", REVOKE_EXTERNAL_COMMAND_PROPERTY_NAME);
            log.error(msg);
            throw new PublisherException(msg);
        }
        // Run internal method to create tempfile and run the command
        List<String> arguments = new ArrayList<>();
        arguments.add(String.valueOf(reason));
        try {
            arguments.add(CertTools.getSubjectDN(cert));
            arguments.add(CertTools.getIssuerDN(cert));
            arguments.add(CertTools.getSerialNumberAsString(cert));
            runWithTempFile(revokeExternalCommandFileName, cert.getEncoded(), revokeFailOnErrorCode, revokeFailOnStandardError, arguments);
        } catch (CertificateEncodingException e) {
            String msg = intres.getLocalizedMessage("publisher.errorcertconversion");
            log.error(msg);
            throw new PublisherException(msg);
        }
        if (log.isTraceEnabled()) {
        	log.trace("<revokeCertificate");
        }
    } // revokeCertificate

    /**
     * Check if the specified external excutable file(s) exist.
     * 
     * @see org.ejbca.core.model.ca.publisher.ICustomPublisher#testConnection()
     */
    @Override
    public void testConnection() throws PublisherConnectionException {
        if (log.isTraceEnabled()) {
        	log.trace("testConnection, Testing connection");
        }
        // Test if specified commands exist
        if (crlExternalCommandFileName != null) {
            if (!(new File(crlExternalCommandFileName)).exists()) {
                String msg = intres.getLocalizedMessage("publisher.commandnotfound", crlExternalCommandFileName);
                log.error(msg);
                throw new PublisherConnectionException(msg);
            }
        }
        if (certExternalCommandFileName != null) {
            if (!(new File(certExternalCommandFileName)).exists()) {
                String msg = intres.getLocalizedMessage("publisher.commandnotfound", certExternalCommandFileName);
                log.error(msg);
                throw new PublisherConnectionException(msg);
            }
        }
        if (revokeExternalCommandFileName != null) {
            if (!(new File(revokeExternalCommandFileName)).exists()) {
                String msg = intres.getLocalizedMessage("publisher.commandnotfound", revokeExternalCommandFileName);
                log.error(msg);
                throw new PublisherConnectionException(msg);
            }
        }
    } // testConnection

    /**
     * Does nothing.
     */
    @Override
    protected void finalize() throws Throwable {
        if (log.isTraceEnabled()) {
        	log.trace("finalize, doing nothing");
        }
        super.finalize();
    } // finalize

    /**
     * Writes a byte-array to a temporary file and executes the given command
     * with the file as argument. The function will, depending on its
     * parameters, fail if output to standard error from the command was
     * detected or the command returns with an non-zero exit code.
     * 
     * @param externalCommand
     *            The command to run.
     * @param bytes
     *            The buffer with content to write to the file.
     * @param failOnCode
     *            Determines if the method should fail on a non-zero exit code.
     * @param failOnOutput
     *            Determines if the method should fail on output to standard
     *            error.
     * @param additionalArguments
     *            Added to the command after the tempfiles name
     * @throws PublisherException
     */
    private void runWithTempFile(String externalCommand, byte[] bytes, boolean failOnCode, boolean failOnOutput, List<String> additionalArguments)
            throws PublisherException {
        // Create temporary file
        File tempFile = null;
        FileOutputStream fos = null;
        try {
            tempFile = File.createTempFile("GeneralPurposeCustomPublisher", ".tmp");
            fos = new FileOutputStream(tempFile);
            fos.write(bytes);
            // fos.close();
        } catch (FileNotFoundException e) {
            String msg = intres.getLocalizedMessage("publisher.errortempfile");
            log.error(msg, e);
            throw new PublisherException(msg);
        } catch (IOException e) {
            try {
                fos.close();
            } catch (IOException e1) {
            }
            tempFile.delete();
            String msg = intres.getLocalizedMessage("publisher.errortempfile");
            log.error(msg, e);
            throw new PublisherException(msg);
        }
        // Exec file from properties with the file as an argument
        String tempFileName = null;
        try {
            tempFileName = tempFile.getCanonicalPath();
            String[] cmdcommand = (externalCommand).split("\\s");
            additionalArguments.add(0, tempFileName);
            if (SystemUtils.IS_OS_WINDOWS) {
                /*
                 * Hack needed for Windows, where Runtime.exec won't consistently encapsulate arguments, leading to arguments
                 * containing spaces (such as Subject DNs) sometimes being parsed as multiple arguments. Bash, on the other hand,
                 * won't parse quote surrounded arguments. 
                 */
                for (int i = 0; i < additionalArguments.size(); i++) {
                    String argument = additionalArguments.get(i);
                    //Add quotes to encapsulate argument. 
                    if (!argument.startsWith("\"") && !argument.endsWith("\"")) {
                        additionalArguments.set(i, "\"" + argument + "\"");
                    }
                }
            }
            String[] cmdargs = additionalArguments.toArray(new String[additionalArguments.size()]);
            String[] cmdarray = new String[cmdcommand.length + cmdargs.length];
            System.arraycopy(cmdcommand, 0, cmdarray, 0, cmdcommand.length);
            System.arraycopy(cmdargs, 0, cmdarray, cmdcommand.length, cmdargs.length);
            Process externalProcess = Runtime.getRuntime().exec(cmdarray, null, null);
            BufferedReader stdError = new BufferedReader(new InputStreamReader(externalProcess.getErrorStream()));
            BufferedReader stdInput = new BufferedReader(new InputStreamReader(externalProcess.getInputStream()));
            while (stdInput.readLine() != null) {} // NOPMD: Required under win32 to avoid lock
            String stdErrorOutput = null;
            // Check errorcode and the external applications output to stderr
            if (((externalProcess.waitFor() != 0) && failOnCode) || (stdError.ready() && failOnOutput)) {
                tempFile.delete();
                String errTemp = null;
                while (stdError.ready() && (errTemp = stdError.readLine()) != null) {
                    if (stdErrorOutput == null) {
                        stdErrorOutput = errTemp;
                    } else {
                        stdErrorOutput += "\n" + errTemp;
                    }
                }
                String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
                if (stdErrorOutput != null) {
                    msg += " - " + stdErrorOutput + " - " + tempFileName;
                }
                log.error(msg);
                throw new PublisherException(msg);
            }
        } catch (IOException e) {
            String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
            throw new PublisherException(msg);
        } catch (InterruptedException e) {
            String msg = intres.getLocalizedMessage("publisher.errorexternalapp", externalCommand);
            Thread.currentThread().interrupt();
            throw new PublisherException(msg);
        } finally {
            try {
                fos.close();
            } catch (IOException e1) {
            }
            // Remove temporary file or schedule for delete if delete fails.
            if (!tempFile.delete()) {
                tempFile.deleteOnExit();
                log.info(intres.getLocalizedMessage("publisher.errordeletetempfile", tempFileName));
            }
        }
    } // runWithTempFile

    @Override
    public boolean willPublishCertificate(int status, int revocationReason) {
        return true;
    }
    
    @Override
    public boolean isReadOnly() {
        return false;
    }
} 
