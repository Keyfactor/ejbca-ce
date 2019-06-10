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

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.authorization.AuthorizationDeniedException;
import org.cesecore.certificates.ca.CAExistsException;
import org.cesecore.certificates.ca.CAOfflineException;
import org.cesecore.keys.token.CryptoTokenAuthenticationFailedException;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.IllegalCryptoTokenException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.cesecore.util.EjbRemoteHelper;
import org.cesecore.util.FileTools;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.cvc.AccessRightEnum;
import org.ejbca.cvc.AuthorizationRoleEnum;
import org.ejbca.cvc.CAReferenceField;
import org.ejbca.cvc.CVCertificate;
import org.ejbca.cvc.CardVerifiableCertificate;
import org.ejbca.cvc.CertificateGenerator;
import org.ejbca.cvc.HolderReferenceField;
import org.ejbca.cvc.exception.ConstructionException;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;

/**
 * Imports a PKCS#8 file and created a new CA from it.
 *
 * @version $Id$
 */
public class CaImportCVCCACommand extends BaseCaAdminCommand {

    private static final Logger log = Logger.getLogger(CaImportCVCCACommand.class);

    private static final String CA_NAME_KEY = "--caname";
    private static final String KEY_FILE_KEY = "-f";
    private static final String CERTIFICATE_FILE_KEY = "-c";
    private static final String DN_KEY = "--dn";
    private static final String SIG_ALG_KEY = "-a";
    private static final String VALIDITY_KEY = "-v";

    {
        registerParameter(new Parameter(CA_NAME_KEY, "CA Name", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Name of the CA"));
        registerParameter(new Parameter(KEY_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "PKCS#8 RSA private key file."));
        registerParameter(new Parameter(CERTIFICATE_FILE_KEY, "Filename", MandatoryMode.MANDATORY, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Certificate file."));
        registerParameter(new Parameter(
                DN_KEY,
                "DN",
                MandatoryMode.OPTIONAL,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Set if a self signed certificate should be generated. Should be in the form of form <C=country,CN=mnemonic,SERIALNUMBER=sequence>. "
                        + "SERIALNUMBER will not be a part of the CAs DN, it is only used to set a specified sequence (should be of form 00001). Can be left out, and a random sequence is then generated."));
        registerParameter(new Parameter(
                SIG_ALG_KEY,
                "Signature Algorithm",
                MandatoryMode.OPTIONAL,
                StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "Set if a self signed certificate should be generated. Signature algorithm can be SHA1WithRSA, SHA256WithRSA, SHA1WithECDSA, SHA224WithECDSA, SHA256WithECDSA, etc."));
        registerParameter(new Parameter(VALIDITY_KEY, "VALIDITY IN DAY", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW, ParameterMode.ARGUMENT,
                "Set if a self signed certificate should be generated. The CA's validity, in days."));
    }

    @Override
    public String getMainCommand() {
        return "importcvcca";
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {

        String caName = parameters.get(CA_NAME_KEY);
        String pkFile = parameters.get(KEY_FILE_KEY);
        String certFile = parameters.get(CERTIFICATE_FILE_KEY);

        // Import key and certificate
        CryptoProviderTools.installBCProvider();
        try {
            byte[] pkbytes;
            try {
                pkbytes = FileTools.readFiletoBuffer(pkFile);
            } catch (FileNotFoundException e) {
                log.error("No such file " + pkFile);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(pkbytes);
            KeyFactory keyfact;
            try {
                keyfact = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException("RSA was not a recognized algorithm in the BC provider (should not happen)", e);
            }
            PrivateKey privKey;
            try {
                privKey = keyfact.generatePrivate(spec);
            } catch (InvalidKeySpecException e) {
                log.debug("Contents of key file was not an RSA key: " + e.getMessage());
                try {
                    keyfact = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
                } catch (NoSuchAlgorithmException e1) {
                    throw new IllegalStateException("EC was not a recognized algorithm in the BC provider (should not happen)", e);
                }
                try {
                    privKey = keyfact.generatePrivate(spec);
                } catch (InvalidKeySpecException e2) {
                    log.error("Contents of key file was neither an RSA key nor an EC key: " + e.getMessage());
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }

            byte[] certbytes;
            try {
                certbytes = FileTools.readFiletoBuffer(certFile);
            } catch (FileNotFoundException e) {
                log.error("No such file " + certFile);
                return CommandResult.FUNCTIONAL_FAILURE;
            }
            Certificate cert = null;
            Certificate cacert = null;

            Collection<Certificate> certs = null;
            try {
                // First check if it was a PEM formatted certificate
                certs = CertTools.getCertsFromPEM(new ByteArrayInputStream(certbytes), Certificate.class);
                final Iterator<Certificate> iter = certs.iterator(); 
                cert = iter.next();
                if (certs.size() > 1) {
                    // If we have ore than one certificate, assume that the second one is the CA certificate (cert is then DVCA and cacert is CVCA)
                    cacert = iter.next();
                }
            } catch (CertificateException e) {
                // This was not a PEM certificate, I hope it's binary...
                try {
                    cert = CertTools.getCertfromByteArray(certbytes, Certificate.class);
                } catch (CertificateParsingException e1) {
                    log.error("File " + certFile + " did not contain a correct certificate.");
                    return CommandResult.FUNCTIONAL_FAILURE;
                }
            }
            PublicKey pubKey = cert.getPublicKey();
            // Verify that the public and private key belongs together
            log.info("Testing keys with algorithm: " + pubKey.getAlgorithm());
            KeyTools.testKey(privKey, pubKey, null);

            String dn = parameters.get(DN_KEY);
            String sigAlg = parameters.get(SIG_ALG_KEY);
            Integer valdays = null;
            if (parameters.get(VALIDITY_KEY) != null) {
                valdays = Integer.parseInt(parameters.get(VALIDITY_KEY));
            }
            try {
                if (dn != null || sigAlg != null || valdays != null) {
                    if (dn == null || sigAlg == null || valdays == null) {
                        log.error("DN, Signature Algorithm and Validity all have to be set to import a CA generating a self signed certificate.");
                    }
                    // Create a self signed CVCA cert from the DN
                    log.info("Generating new self signed CVCA certificate.");
                    String country = CertTools.getPartFromDN(dn, "C");
                    String mnemonic = CertTools.getPartFromDN(dn, "CN");
                    String seq = CertTools.getPartFromDN(dn, "SERIALNUMBER");
                    if (StringUtils.isEmpty(seq)) {
                        seq = RandomStringUtils.randomNumeric(5);
                        log.info("No sequence given, using random 5 number sequence: " + seq);
                    }
                    HolderReferenceField holderRef = new HolderReferenceField(country, mnemonic, seq);
                    CAReferenceField caRef = new CAReferenceField(holderRef.getCountry(), holderRef.getMnemonic(), holderRef.getSequence());
                    AuthorizationRoleEnum authRole = AuthorizationRoleEnum.CVCA;
                    Date notBefore = new Date();
                    Calendar notAfter = Calendar.getInstance();
                    notAfter.add(Calendar.DAY_OF_MONTH, valdays);
                    CVCertificate cvc;
                    try {
                        cvc = CertificateGenerator.createCertificate(pubKey, privKey, sigAlg, caRef, holderRef, authRole,
                                AccessRightEnum.READ_ACCESS_DG3_AND_DG4, notBefore, notAfter.getTime(), BouncyCastleProvider.PROVIDER_NAME);
                    } catch (SignatureException e) {
                        throw new IllegalStateException("Unknown SignatureException was encountered.", e);
                    } catch (ConstructionException e) {
                        throw new IllegalStateException("Unknown ConstructionException was encountered.", e);
                    } catch (IOException e) {
                        throw new IllegalStateException("Unknown IOException was encountered.", e);
                    }
                    cert = new CardVerifiableCertificate(cvc);
                } else  if (cacert == null) {
                    log.info("Using passed in self signed certificate.");
                } else {
                    log.info("Using second cert in passed in chain as CVCA certificate, first one as DVCA certificate");
                }
                try {
                    if (cacert != null) {
                        cert.verify(cacert.getPublicKey());
                    } else {
                        cert.verify(pubKey);
                    }
                } catch (SignatureException e) {
                    throw new IllegalStateException("Can not verify certificate.", e);
                } catch (CertificateException e) {
                    throw new IllegalStateException("An encoding error was encountered.", e);
                }
            } catch (NoSuchAlgorithmException e) {
                log.error("Algorithm " + sigAlg + " was not recognized.");
            }

            Certificate[] chain = new Certificate[certs == null ? 1 : certs.size()];
            chain[0] = cert;
            if (chain.length > 1) {
                chain[1] = cacert;
            }
            try {
                EjbRemoteHelper.INSTANCE.getRemoteSession(CAAdminSessionRemote.class).importCAFromKeys(getAuthenticationToken(), caName, "foo123",
                        chain, pubKey, privKey, null, null);
                return CommandResult.SUCCESS;
            } catch (CryptoTokenAuthenticationFailedException e) {
                log.error(e.getMessage());
            } catch (CryptoTokenOfflineException e) {
                log.error(e.getMessage());
            } catch (IllegalCryptoTokenException e) {
                log.error(e.getMessage());
            } catch (CAExistsException e) {
                log.error("CA already exists: " + caName);
            } catch (CAOfflineException e) {
                log.error(e.getMessage());
            } catch (AuthorizationDeniedException e) {
                log.error(e.getMessage());
            }
            return CommandResult.FUNCTIONAL_FAILURE;
        } catch (NoSuchProviderException e) {
            throw new IllegalStateException("BouncyCastle provider could not be found.", e);
        } catch (InvalidKeyException e) {
            throw new IllegalStateException("Wrong key was supplied when verifying newly generated certificate.", e);
        }

    } // execute

    @Override
    public String getCommandDescription() {
        return "Imports a PKCS#8 file and creates a new CVC CA from it";

    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append("This command either:\n"
                + "    * Imports a private key and a self signed CVCA certificate and creates a CVCA (if only the mandatory arguments are defined)\n"
                + "or\n"
                + "    * Imports a private key and generates a new self signed CVCA certificate with the given DN and creates a CVCA (if ALL of the optional arguments are defined as well).\n"
                + "or\n"
                + "    * Imports a private key and chain with first certificate a DVCA and the second one a CVCA certificate, creating a DVCA assuming the CVCA (certificate) has already been imported.\n");
        return sb.toString();
    }
    
    @Override
    protected Logger getLogger() {
        return log;
    }
}
