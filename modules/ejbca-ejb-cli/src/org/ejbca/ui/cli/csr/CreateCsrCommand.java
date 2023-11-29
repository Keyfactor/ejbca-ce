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
package org.ejbca.ui.cli.csr;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang3.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.crypto.algorithm.AlgorithmTools;
import com.keyfactor.util.keys.KeyTools;

/**
 * Utility command for creating CSRs
 */
public class CreateCsrCommand extends EjbcaCommandBase {

    private static final String SDN_ARG = "--subjectdn";
    
    private static final String KEYALG_ARG = "--keyalg";
    private static final String ALT_KEYALG_ARG = "--altkeyalg";

    private static final String KEYSPEC_ARG = "--keyspec";
    private static final String ALT_KEYSPEC_ARG = "--altkeyspec";

    private static final String PUBLICKEY_ARG = "--pubkey";
    private static final String PRIVATEKEY_ARG = "--privkey";
    private static final String ALT_PUBLICKEY_ARG = "--altpubkey";
    private static final String ALT_PRIVATEKEY_ARG = "--altprivkey";
    
    private  static final String DESTINATION_ARG = "--destination";

    private static final Set<String> RSA_KEY_SIZES = new LinkedHashSet<>(Arrays.asList("1024", "1536", "2048", "3072", "4096", "6144", "8192"));
    private static final Set<String> EC_CURVES = AlgorithmTools.getNamedEcCurvesMap(true).keySet();

    private static final Logger log = Logger.getLogger(CreateCsrCommand.class);

    {
        registerParameter(new Parameter(SDN_ARG, "Subject DN", MandatoryMode.MANDATORY, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Requested Subject DN of the enrolled user."));
        registerParameter(new Parameter(PUBLICKEY_ARG, "Public Key File", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Complete path to the public key to sign. Key cipher and algorithm arguments will be ignored if this is provided."));
        registerParameter(new Parameter(PRIVATEKEY_ARG, "Private Key file", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Complete path to the private key associated with the public key. Key cipher and algorithm arguments will be ignored if this is provided."));
        
        registerParameter(new Parameter(ALT_PUBLICKEY_ARG, "Alternative Public Key File", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Complete path to the public key to sign. Key cipher and algorithm arguments will be ignored if this is provided."));
        registerParameter(new Parameter(ALT_PRIVATEKEY_ARG, "Alternative Private Key file", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Complete path to the private key associated with the alternative public key. Key cipher and algorithm arguments will be ignored if this is provided."));

        registerParameter(new Parameter(KEYALG_ARG, "cipher", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Cipher must be one of [ " + AlgorithmConstants.KEYALGORITHM_RSA + ", " + AlgorithmConstants.KEYALGORITHM_EC + ", "
                        + AlgorithmConstants.KEYALGORITHM_ED25519 + ", " + AlgorithmConstants.KEYALGORITHM_ED448 + ", "
                        + AlgorithmConstants.KEYALGORITHM_DILITHIUM2 + ", " + AlgorithmConstants.KEYALGORITHM_DILITHIUM3 + ", "
                        + AlgorithmConstants.KEYALGORITHM_DILITHIUM5 + ", " + AlgorithmConstants.KEYALGORITHM_FALCON512 + ", "
                        + AlgorithmConstants.KEYALGORITHM_FALCON1024 + "].  Omit if using existing keys."));

        StringBuilder ecCurvesFormatted = new StringBuilder();
        ecCurvesFormatted.append("[");
        for (String curveName : EC_CURVES) {
            ecCurvesFormatted.append(" ").append(curveName).append(",");
        }
        ecCurvesFormatted.deleteCharAt(ecCurvesFormatted.lastIndexOf(","));
        ecCurvesFormatted.append(" ]");
        registerParameter(new Parameter(KEYSPEC_ARG, "Key Specification", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Key Specification.\n If cipher was RSA, must be one of [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ].\n If cipher was EC, must be one of "
                        + ecCurvesFormatted + ". Should be omitted for Ed25519 and Ed448 or a PQ algorithm. Omit if using existing keys."));

        registerParameter(new Parameter(ALT_KEYALG_ARG, "cipher", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Alternative cipher must be one of [ " + AlgorithmConstants.KEYALGORITHM_RSA + ", " + AlgorithmConstants.KEYALGORITHM_EC + ", "
                        + AlgorithmConstants.KEYALGORITHM_ED25519 + ", " + AlgorithmConstants.KEYALGORITHM_ED448 + ", "
                        + AlgorithmConstants.KEYALGORITHM_DILITHIUM2 + ", " + AlgorithmConstants.KEYALGORITHM_DILITHIUM3 + ", "
                        + AlgorithmConstants.KEYALGORITHM_DILITHIUM5 + ", " + AlgorithmConstants.KEYALGORITHM_FALCON512 + ", "
                        + AlgorithmConstants.KEYALGORITHM_FALCON1024 + "].  Omit if using existing keys."));

        registerParameter(new Parameter(ALT_KEYSPEC_ARG, "Key Specification", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "Key Specification.\n If cipher was RSA, must be one of [ 1024, 1536, 2048, 3072, 4096, 6144, 8192 ].\n If cipher was EC, must be one of "
                        + ecCurvesFormatted + ". Should be omitted for Ed25519 and Ed448 or a PQ algorithm. Omit if using existing keys."));
        
        registerParameter(new Parameter(DESTINATION_ARG, "directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT, "Destination directory for the CSR, and keys if generated. Optional, pwd will be used if left out."));
    }

    @Override
    protected CommandResult execute(ParameterContainer parameters) {
        CryptoProviderTools.installBCProvider();
        
        final File destination; 
        if (parameters.containsKey(DESTINATION_ARG)) {
            final String destinationDirName = parameters.get(DESTINATION_ARG);
            destination = new File(destinationDirName);
            if (!destination.isDirectory() || !destination.canWrite()) {
                getLogger()
                        .error("Directory " + destinationDirName + " was not a directory, or could not be written to.");
                return CommandResult.CLI_FAILURE;
            }
        } else {
            destination = new File(System.getProperty("user.dir"));
        }
        
        final String subjectDn = parameters.get(SDN_ARG);
        
        final String pubkeyFilename = parameters.get(PUBLICKEY_ARG);
        final String privkeyFilename = parameters.get(PRIVATEKEY_ARG); 
        
        final KeyPair primaryKeyPair;
        
        final KeyPair alternativeKeyPair;
        
        if(StringUtils.isEmpty(pubkeyFilename) ^ StringUtils.isEmpty(privkeyFilename)) {
            log.error("If using an existing key pair, both keys must be supplied as arguments.");
            return CommandResult.CLI_FAILURE;
        } else if(!StringUtils.isEmpty(pubkeyFilename)) {
            //Keys were provided. 
            try {
                primaryKeyPair = new KeyPair(readPublicKey(pubkeyFilename), readPrivateKey(privkeyFilename));
            } catch (IOException e) {
                getLogger().error("Could not read either primary key: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }          
            //Check for an alternative keypair
            String alternativePubkeyFilename = parameters.get(ALT_PUBLICKEY_ARG);
            String alternativePrivkeyFilename = parameters.get(ALT_PRIVATEKEY_ARG);
            
            if(StringUtils.isEmpty(alternativePubkeyFilename) ^ StringUtils.isEmpty(alternativePrivkeyFilename)) {
                log.error("If using an existing alternative key pair, both keys must be supplied as arguments.");
                return CommandResult.CLI_FAILURE;
            } else if(!StringUtils.isEmpty(alternativePubkeyFilename)) {
                //Keys were provided. 
                try {
                    alternativeKeyPair = new KeyPair(readPublicKey(alternativePubkeyFilename), readPrivateKey(alternativePrivkeyFilename));
                } catch (IOException e) {
                    getLogger().error("Could not read either primary key: " + e.getMessage());
                    return CommandResult.CLI_FAILURE;
                }    
            } else {
                alternativeKeyPair = null;
            }
           
        } else {
            
            //Keys should be generated
            final String keySpec = parameters.get(KEYSPEC_ARG);
            final String keyAlg = parameters.get(KEYALG_ARG);
                log.info("Generating primary key pair: " + keyAlg + " - " + keySpec);
            
            if(StringUtils.isEmpty(keyAlg)) {
                getLogger().error("No keys were provided, nor was a key algorithm for key generation.");
                return CommandResult.CLI_FAILURE;
            }
            
            try {
                primaryKeyPair = generateKeypair(keyAlg, keySpec);
            } catch (IOException e) {
                getLogger().error("Could not create primary key: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }
            
            final String altKeySpec = parameters.get(ALT_KEYSPEC_ARG);
            final String altKeyAlg = parameters.get(ALT_KEYALG_ARG);
            
            //Create an alternative keypair, if requested
            if(!StringUtils.isEmpty(altKeyAlg)) {
                try {
                    alternativeKeyPair = generateKeypair(altKeyAlg, altKeySpec);
                } catch (IOException e) {
                    getLogger().error("Could not create alternative key: " + e.getMessage());
                    return CommandResult.CLI_FAILURE;
                }
                
            } else {
                alternativeKeyPair = null;
            }
        }
        
        final PKCS10CertificationRequestBuilder pkcs10CertificationRequestBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(subjectDn),
                primaryKeyPair.getPublic());
        
        List<String> primarySigAlgs = AlgorithmTools.getSignatureAlgorithms(primaryKeyPair.getPublic());
        if (primarySigAlgs.size() == 0) {
            log.error("Unable to generate CSR, no signature algorithms available for public key of type: " + primaryKeyPair.getPublic().getClass().getName());
            return CommandResult.CLI_FAILURE;
        }
        
        final String signatureAlgorithm;
        if ( primaryKeyPair.getPublic() instanceof RSAPublicKey ) {
            signatureAlgorithm = "SHA256WithRSA"; // Avoid SHA1WithRSA that AlgorithmTools.getSignatureAlgorithms will return
        } else {
            signatureAlgorithm = primarySigAlgs.get(0);
        }
        log.info("Using signature algorithm: " + signatureAlgorithm);
        final ContentSigner contentSigner;
        try {
            contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).setProvider(BouncyCastleProvider.PROVIDER_NAME).build(primaryKeyPair.getPrivate());
        } catch (OperatorCreationException e) {
            log.error("Could not create signer for " + signatureAlgorithm + ". Error message: " + e.getMessage());
            log.error("debug", e);
            return CommandResult.CLI_FAILURE;
        } 
        
        PKCS10CertificationRequest pkcs10CertificationRequest;
        if(alternativeKeyPair != null) {
            List<String> alternativeSigAlgs = AlgorithmTools.getSignatureAlgorithms(alternativeKeyPair.getPublic());
            final String alternativeSignatureAlgorithm;
            if ( alternativeKeyPair.getPublic() instanceof RSAPublicKey ) {
                alternativeSignatureAlgorithm = "SHA256WithRSA"; // Avoid SHA1WithRSA that AlgorithmTools.getSignatureAlgorithms will return
            } else {
                alternativeSignatureAlgorithm = alternativeSigAlgs.get(0);
            }
            ContentSigner altSigner;
            try {
                altSigner = new JcaContentSignerBuilder(alternativeSignatureAlgorithm)
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(alternativeKeyPair.getPrivate());
            } catch (OperatorCreationException e) {
                log.error("Could not create signer for " + alternativeSignatureAlgorithm + ". Error message: " + e.getMessage());
                return CommandResult.CLI_FAILURE;
            }
            
            pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner, SubjectPublicKeyInfo.getInstance(alternativeKeyPair.getPublic().getEncoded()), altSigner);
        } else {
            pkcs10CertificationRequest = pkcs10CertificationRequestBuilder.build(contentSigner);
        }
        log.error("Certificate Signing Request:");
        String csr = CertTools.buildCsr(pkcs10CertificationRequest);
        log.error(csr);
        
        //Write the CSR to disk as a PEM
        File csrFile = new File(destination, "certificateSigningRequest.csr");
        
        try {
            PrintWriter printWriter = new PrintWriter(new FileWriter(csrFile));
            printWriter.write(csr);
            printWriter.close();
            log.error("Wrote CSR to " + csrFile.getCanonicalPath());
        } catch (IOException e) {
           log.error("Could not write CSR to file. " + e.getMessage());
           return CommandResult.FUNCTIONAL_FAILURE;
        } 
        
        //If keys were generated, write them to disk as well
        if(StringUtils.isEmpty(pubkeyFilename)) {
            try {
                writeKeyToFile(CertTools.getPEMFromPublicKey(primaryKeyPair.getPublic().getEncoded()), new File(destination, "pubkey.pem"));
                writeKeyToFile(CertTools.getPEMFromPrivateKey(primaryKeyPair.getPrivate().getEncoded()), new File(destination, "privkey.pem"));
                if(alternativeKeyPair != null) {
                    writeKeyToFile(CertTools.getPEMFromPublicKey(alternativeKeyPair.getPublic().getEncoded()), new File(destination, "altpubkey.pem"));
                    writeKeyToFile(CertTools.getPEMFromPrivateKey(alternativeKeyPair.getPrivate().getEncoded()), new File(destination, "altprivkey.pem"));
                }
            } catch (IOException e) {
                return CommandResult.FUNCTIONAL_FAILURE;
            }
        }
        
        return CommandResult.SUCCESS;
    }
    
    private void writeKeyToFile(byte[] encodedKey, File destination) throws IOException {
        try {
            PrintWriter printWriter = new PrintWriter(new FileWriter(destination));
            printWriter.write(new String(encodedKey));
            printWriter.close();
            log.error("Wrote Public Key to " + destination.getCanonicalPath());
        } catch (IOException e) {
           log.error("Could not write Public Key to file. " + e.getMessage());
           throw e;
        } 
    }

    @Override
    public String getMainCommand() {
        return "gencsr";
    }

    @Override
    public String getCommandDescription() {

        return "Create a CSR";
    }

    @Override
    public String getFullHelpText() {
        return "Creates a CSR, either using already existing keys or may generate those keys locally. Can create hybrid PKCS#10 requests as well.";
    }

    @Override
    protected Logger getLogger() {
        return log;
    }
    
    private KeyPair generateKeypair(final String keyAlg, final String keySpec) throws IOException {
        final String keyAlgorithm;
        switch (keyAlg.toUpperCase()) {
        case "RSA":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_RSA;
            if (!RSA_KEY_SIZES.contains(keySpec)) {
                throw new IOException("Key size " + keySpec + " is invalid for RSA Keys.");
            }
            break;
        case "EC":
        case "ECDSA":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_EC;
            if (!EC_CURVES.contains(keySpec)) {
                throw new IOException(keySpec + " is not a known EC curve.");
            }
            break;
        case "ED25519":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_ED25519;
            break;
        case "ED448":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_ED448;
            break;
        case "DILITHIUM2":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DILITHIUM2;
            break;
        case "DILITHIUM3":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_DILITHIUM3;
            break;
        case "FALCON-512":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_FALCON512;
            break;
        case "FALCON-1024":
            keyAlgorithm = AlgorithmConstants.KEYALGORITHM_FALCON1024;
            break;             
        default:
            throw new IOException("Key Algorithm " + keyAlg + " was unknown.");
        }
        try {
            return KeyTools.genKeys(keySpec, keyAlgorithm);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException("Caught invalid parameter exception: " + e.getMessage());
        }
    }
    
    private PublicKey readPublicKey(final String filename) throws IOException {
        FileReader keyReader = new FileReader(new File(filename));
        try (PemReader pemReader = new PemReader(keyReader)) {
            PemObject pemObject = pemReader.readPemObject();
            byte[] content = pemObject.getContent();
            return KeyTools.getPublicKeyFromBytes(content);
        }
    }

    private PrivateKey readPrivateKey(final String filename) throws IOException {
        try (FileReader keyReader = new FileReader(new File(filename))) {

            PEMParser pemParser = new PEMParser(keyReader);
            Object pemObject = pemParser.readObject();
            PrivateKeyInfo privateKeyInfo;
            if (pemObject instanceof PEMKeyPair) {
                privateKeyInfo = ((PEMKeyPair) pemObject).getPrivateKeyInfo();
            } else {
                privateKeyInfo = PrivateKeyInfo.getInstance(pemParser.readObject());
            }
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            return converter.getPrivateKey(privateKeyInfo);
        }
    }

}
