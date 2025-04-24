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
package org.ejbca.ui.cli.ocsp;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.io.IOUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.FileTools;
import com.keyfactor.util.SHA1DigestCalculator;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;

/**
 * Command to perform a simple OCSP request
 */
public class OcspRequestCommand extends EjbcaCliUserCommandBase {

    private static final Logger log = Logger.getLogger(OcspRequestCommand.class);

    private static final String CERTIFICATE_FILE_KEY = "--cert";
    private static final String ISSUING_CA_FILE_KEY = "--issuer";
    private static final String HOST_URL_KEY = "--url";
    
    {
        registerParameter(new Parameter(CERTIFICATE_FILE_KEY, "Certificate File", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Certificate to check the status of. Must be PEM encoded"));
        registerParameter(new Parameter(ISSUING_CA_FILE_KEY, "Certificate File", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "The Issuing CA. Must be PEM encoded"));
        registerParameter(new Parameter(HOST_URL_KEY, "VA URL", MandatoryMode.MANDATORY, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Complete path to the VA, i.e. http://127.0.0.1:8080/ejbca/publicweb/status/ocsp"));
    }
    
    @Override
    public String getMainCommand() {
        return "request";
    }

    @Override
    public String getCommandDescription() {
        return "Performs an OCSP request.";
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {

        final String certfilePath = parameters.get(CERTIFICATE_FILE_KEY);
        
        final X509Certificate certificate;
        try {
            certificate = loadcert(certfilePath);
        } catch (FileNotFoundException e) {
            log.error("File " + certfilePath + " was not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CertificateException e) {
            log.error("PEM in file " + certfilePath + " could not be read.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            log.error("File " + certfilePath + " does not seem to contain a PEM encoded certificate.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        
        final String caCertificateFilePath = parameters.get(ISSUING_CA_FILE_KEY);
        final X509Certificate caCertificate;
        
        try {
            caCertificate = loadcert(caCertificateFilePath);
        } catch (FileNotFoundException e) {
            log.error("File " + caCertificateFilePath + " was not found.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (CertificateException e) {
            log.error("PEM in file " + caCertificateFilePath + " could not be read.");
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (IOException e) {
            log.error("File " + caCertificateFilePath + " does not seem to contain a PEM encoded certificate.");
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        final String urlPath = parameters.get(HOST_URL_KEY);
        
        final BigInteger certificateSerialNumber = CertTools.getSerialNumber(certificate);
        OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
        OCSPReq request;
        try {
            ocspReqBuilder.addRequest(new JcaCertificateID(SHA1DigestCalculator.buildSha1Instance(), caCertificate, certificateSerialNumber));
            request = ocspReqBuilder.build();
        } catch (CertificateEncodingException | OCSPException e) {
            log.error("Could not construct OCSP request: " + e.getMessage());
            return CommandResult.CLI_FAILURE;
        }
        URL url;
        try {
            url = new URL(urlPath);
        } catch (MalformedURLException e) {
            log.error("Incorrectly formatted URL: " + e.getMessage());
            return CommandResult.CLI_FAILURE;
        }
        try {
            OCSPResp ocspResponse = sendOcspPost(url, request.getEncoded());
            if(ocspResponse == null) {
                log.error("Could not contact OCSP responder at " + urlPath);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            BasicOCSPResp basicOCSPResp = (BasicOCSPResp) ocspResponse.getResponseObject();
            X509CertificateHolder[] chain = basicOCSPResp.getCerts();
            if (!basicOCSPResp
                    .isSignatureValid(new JcaContentVerifierProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build(chain[0]))) {
                throw new OCSPException("OCSP response did not verify.");
            }

            log.info("Received OCSP Response from server:");
            log.info("Response was succesfully validated.");
            log.info("Response was signed with: " + AlgorithmTools.getAlgorithmNameFromOID(basicOCSPResp.getSignatureAlgOID()) );
            List<X509Certificate> signingChain = CertTools.convertToX509CertificateList(Arrays.asList(basicOCSPResp.getCerts()));
            if (signingChain.size() != 0) {
                log.info("Response contained a signing chain with the following serial number entries:");
                for (int i = 0; i < signingChain.size(); i++) {
                    X509Certificate chainCertificate = signingChain.get(i);
                    log.info("    " + i + ": " + CertTools.getSerialNumberAsString(chainCertificate) + (i == 0 ? " (OCSP Certificate)" : " (CA Certificate)"));
                }
            } else {
                log.info("Response was returned without a signing chain.");
            }

            SingleResp[] responses = basicOCSPResp.getResponses();
            log.info("Response contained " + responses.length + " individual responses.");
            for(SingleResp response : responses) {
                final String status;
                
                if(response.getCertStatus() == null) {
                    status = "Good";
                } else if(response.getCertStatus() instanceof RevokedStatus) {
                    status = "Revoked";
                } else if(response.getCertStatus() instanceof UnknownStatus) {
                    status = "Unknown";
                } else {
                    status = "Unknown";
                }
                log.info("Status of certificate with SN " + response.getCertID().getSerialNumber().toString(16) + ": " + status);
                
            }
        } catch (OperatorCreationException | CertificateException | IOException | OCSPException e) {
            log.error("Failed to send OCSP request: " + e.getMessage());
            return CommandResult.FUNCTIONAL_FAILURE;
        }
        
        return CommandResult.SUCCESS;
    }

    @Override
    public String getFullHelpText() {
        StringBuilder stringBuilder = new StringBuilder();
        stringBuilder.append(getCommandDescription() + "\n\n");
        stringBuilder.append("This is currently a basic testing tool, and lacks the following functionality (amongst others):\n");
        stringBuilder.append("    - Signed Requests");
        stringBuilder.append("    - Nonce extension");
        return stringBuilder.toString();
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

    @Override
    public String[] getCommandPath() {
        return new String[] { "ocsp" };
    }

    private OCSPResp sendOcspPost(final URL url, byte[] ocspPayload) throws IOException, OCSPException, OperatorCreationException, CertificateException {
        // POST the OCSP request
        HttpURLConnection con = (HttpURLConnection) url.openConnection();
        // we are going to do a POST
        con.setDoOutput(true);
        con.setRequestMethod("POST");

        // POST it
        con.setRequestProperty("Content-Type", "application/ocsp-request");
        OutputStream os = con.getOutputStream();
        os.write(ocspPayload);
        os.close();
        if (con.getResponseCode() != 200) {
            return null; // if it is an http error code we don't need to test any more
        }
        OCSPResp response = new OCSPResp(IOUtils.toByteArray(con.getInputStream()));
        return response;
    }
    
    private X509Certificate loadcert(final String filename) throws IOException, CertificateException {
        File certificateFile = new File(filename);
        if (!certificateFile.exists()) {
            throw new FileNotFoundException(filename + " is not a file.");
        }
        byte[] bytes = FileTools.getBytesFromPEM(FileTools.readFiletoBuffer(filename), "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----");
        X509Certificate x509Certificate = CertTools.getCertfromByteArray(bytes, X509Certificate.class);
        return x509Certificate;

    }

}
