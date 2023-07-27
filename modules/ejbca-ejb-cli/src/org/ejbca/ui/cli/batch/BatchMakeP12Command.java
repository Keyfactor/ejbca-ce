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

package org.ejbca.ui.cli.batch;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSessionRemote;
import org.cesecore.certificates.certificate.IllegalKeyException;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.config.GlobalCesecoreConfiguration;
import org.cesecore.configuration.GlobalConfigurationSessionRemote;
import org.cesecore.util.EjbRemoteHelper;
import org.ejbca.config.GlobalConfiguration;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.EndEntityAccessSessionRemote;
import org.ejbca.core.ejb.ra.EndEntityManagementSession;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.EndEntityProfileSessionRemote;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryInformation;
import org.ejbca.ui.cli.infrastructure.command.CommandResult;
import org.ejbca.ui.cli.infrastructure.command.EjbcaCliUserCommandBase;
import org.ejbca.ui.cli.infrastructure.parameter.Parameter;
import org.ejbca.ui.cli.infrastructure.parameter.ParameterContainer;
import org.ejbca.ui.cli.infrastructure.parameter.enums.MandatoryMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.ParameterMode;
import org.ejbca.ui.cli.infrastructure.parameter.enums.StandaloneMode;
import org.ejbca.util.keystore.P12toPEM;

import com.keyfactor.util.CertTools;
import com.keyfactor.util.CryptoProviderTools;
import com.keyfactor.util.EJBTools;
import com.keyfactor.util.crypto.algorithm.AlgorithmConstants;
import com.keyfactor.util.keys.KeyTools;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

/**
 * This class generates keys and request certificates for all users with status NEW. The result is
 * generated PKCS12, JKS or PEM-files.
 */
public class BatchMakeP12Command extends EjbcaCliUserCommandBase {

    private static final String END_ENTITY_USERNAME_KEY = "--username";
    private static final String END_ENTITY_KEY_ALG = "--keyalg";
    private static final String END_ENTITY_KEY_SPEC = "--keyspec";
    private static final String DIRECTORY_KEY = "-dir";

    private static final Logger log = Logger.getLogger(BatchMakeP12Command.class);

    {
        registerParameter(new Parameter(END_ENTITY_USERNAME_KEY, "End entity username", MandatoryMode.OPTIONAL, StandaloneMode.ALLOW,
                ParameterMode.ARGUMENT,
                "The name of the end entity to generate the key for. If omitted, keys will be generated for all users with status NEW or FAILED"));
        registerParameter(new Parameter(DIRECTORY_KEY, "Directory", MandatoryMode.OPTIONAL, StandaloneMode.FORBID, ParameterMode.ARGUMENT,
                "The name of the directory to store the keys to. If not specified, the current EJBCA_HOME/p12 directory will be used."));
        registerParameter(new Parameter(END_ENTITY_KEY_ALG, "Key generation algorithm", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Key algorithm for generated key (RSA, ECDSA, DSA, Ed25519, Ed448), see conf/batchtool.properties for more information. If omitted values from batchtool.properties are used"));
        registerParameter(new Parameter(END_ENTITY_KEY_SPEC, "Key generation spec", MandatoryMode.OPTIONAL, StandaloneMode.FORBID,
                ParameterMode.ARGUMENT,
                "Key specification for generated key (1024, 2048, Ed25519, Ed448, prime256v1 or other ECDSA curve name), see conf/batchtool.properties for more information. If omitted values from batchtool.properties are used"));
    }

    private BatchToolProperties props = null;

    /** Lazy loading of properties so we don't have to read it when CliCommandHelper goes through all commands.
     * @return BatchToolProperties, never null
     */
    private BatchToolProperties getProps() {
        if (props == null) {
            props = new BatchToolProperties(log);
        }
        return props;
    }

    /**
     * Where created P12-files are stored, default p12
     */
    private String mainStoreDir = "";
    private Boolean usekeyrecovery = null;

    @Override
    public String getMainCommand() {
        return "batch";
    }

    @Override
    public String getCommandDescription() {
        return "Batch generate keys and certificates.";
    }

    @Override
    public String getFullHelpText() {
        StringBuilder sb = new StringBuilder();
        sb.append(getCommandDescription() + "\n\n");
        String indent = "    * ";
        sb.append("For end entities to be batch generated, they must fulfill the following criteria:" + "\n");
        sb.append(indent + "They must have status NEW, FAILED or KEYRECOVER."+ "\n");
        sb.append(indent + "Cleartext password must be set."+ "\n");
        sb.append(indent + "Token type must be JKS, P12, BCFKS or PEM."+ "\n");
        return sb.toString();
    }

    @Override
    public CommandResult execute(ParameterContainer parameters) {
        try {
            String username = parameters.get(END_ENTITY_USERNAME_KEY);
            String directory = parameters.get(DIRECTORY_KEY);
            if (directory == null) {
                directory = getHomeDir() + "p12";
            }

            if (username == null) {
                log.info("Use '" + getMainCommand() + " --help' for additional options.");
            }
            final String keyAlg = parameters.get(END_ENTITY_KEY_ALG);
            final String keySpec = parameters.get(END_ENTITY_KEY_SPEC);
            if (StringUtils.isEmpty(keyAlg) && !StringUtils.isEmpty(keySpec)) {
                log.info("If specifying --keyalg or --keyspec, both must be specified, see --help' for additional options.");                
            }
            if (!StringUtils.isEmpty(keyAlg) && StringUtils.isEmpty(keySpec)) {
                log.info("If specifying --keyalg or --keyspec, both must be specified, see --help' for additional options.");                
            }
            if (!StringUtils.isEmpty(keyAlg) && !StringUtils.isEmpty(keySpec)) {
                getProps().setKeyAlg(keyAlg);
                getProps().setKeySpec(keySpec);
            }
            // Bouncy Castle security provider
            CryptoProviderTools.installBCProviderIfNotAvailable();
            // Create subdirectory 'p12' if it does not exist
            File dir = new File(directory).getCanonicalFile();
            dir.mkdir();
            setMainStoreDir(directory);
            String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generateindir", dir);
            log.info(iMsg);
            if (username != null) {
                createKeysForUser(username);
            } else {
                // Make P12 for all NEW users in local DB
                createAllNew();
                // Make P12 for all FAILED users in local DB
                createAllFailed();
                // Make P12 for all KEYRECOVERABLE users in local DB
                createAllKeyRecover();
            }
            return CommandResult.SUCCESS;
        } catch (Exception e) {
            e.printStackTrace();
            return CommandResult.FUNCTIONAL_FAILURE;
        }
    }

    private boolean getUseKeyRecovery() {
        if (usekeyrecovery == null) {
            usekeyrecovery = ((GlobalConfiguration) EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class)
                    .getCachedConfiguration(GlobalConfiguration.GLOBAL_CONFIGURATION_ID)).getEnableKeyRecovery();
        }
        return usekeyrecovery;
    }

  

    /**
     * Sets the location where generated P12-files will be stored, full name
     * will be: mainStoreDir/username.p12.
     * 
     * @param dir
     *            existing directory
     */
    private void setMainStoreDir(String dir) {
        mainStoreDir = dir;
    }

    /**
     * Stores keystore.
     * 
     * @param ks
     *            KeyStore
     * @param username
     *            username, the owner of the keystore
     * @param kspassword
     *            the password used to protect the peystore
     * @throws IOException
     *             if directory to store keystore cannot be created
     */
    private void storeKeyStore(KeyStore ks, String username, String kspassword, int keystoreType) throws IOException,
            KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException {
        if (log.isTraceEnabled()) {
            log.trace(">storeKeyStore: ks=" + ks.toString() + ", username=" + username);
        }
        // Where to store it?
        if (mainStoreDir == null) {
            throw new IOException("Can't find directory to store keystore in.");
        }

        if (!new File(mainStoreDir).exists()) {
            new File(mainStoreDir).mkdir();
            log.info("Directory '" + mainStoreDir + "' did not exist and was created.");
        }

        String keyStoreFilename = mainStoreDir + "/" + username;

        if (keystoreType == SecConst.TOKEN_SOFT_JKS) {
            keyStoreFilename += ".jks";
        } else {
            keyStoreFilename += ".p12";
        }

        // If we should also create PEM-files, do that
        if (keystoreType == SecConst.TOKEN_SOFT_PEM) {
            String PEMfilename = mainStoreDir + "/pem";
            P12toPEM p12topem = new P12toPEM(ks, kspassword);
            p12topem.setExportPath(PEMfilename);
            p12topem.createPEM();
        } else {
            try (final FileOutputStream fileOutputStream = new FileOutputStream(keyStoreFilename);) {
                ks.store(fileOutputStream, kspassword.toCharArray());
            }
        }

        log.debug("Keystore stored in " + keyStoreFilename);
        if (log.isTraceEnabled()) {
            log.trace("<storeKeyStore: ks=" + ks.toString() + ", username=" + username);
        }
    }

    /**
     * Creates files for a user, sends request to CA, receives reply and creates
     * P12.
     * 
     * @param username
     *            username
     * @param password
     *            user's password
     * @param caId
     *            of CA used to issue the keystore certificates
     * @param keyPair
     *            a previously generated keypair
     * @param keystoreType
     *            one of the constants from {@link SecConst}
     * @param savekeys
     *            if generated keys should be saved in db (key recovery)
     * @param orgCert
     *            if an original key recovered cert should be reused, null
     *            indicates generate new cert.
     * @throws Exception
     *             if the certificate is not an X509 certificate
     * @throws Exception
     *             if the CA-certificate is corrupt
     * @throws Exception
     *             if verification of certificate or CA-cert fails
     * @throws Exception
     *             if keyfile (generated by ourselves) is corrupt
     */

    private void createKeysForUser(String username, String password, int caId, KeyPair keyPair, int keystoreType, boolean savekeys,
                                   X509Certificate orgCert) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">createUser: username=" + username);
        }

        X509Certificate cert = null;

        if (orgCert != null) {
            cert = orgCert;
            boolean finishUser = EjbRemoteHelper.INSTANCE.getRemoteSession(CaSessionRemote.class).getCAInfo(getAuthenticationToken(), caId)
                    .getFinishUser();
            if (finishUser) {
                EndEntityInformation userdata = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                        getAuthenticationToken(), username);
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSession.class).finishUser(userdata);
            }

        } else {
            // Create self signed certificate, because ECDSA keys are not
            // serializable
            String sigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_RSA;
            if (getProps().getKeyAlg().equals("ECDSA")) {
                sigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            } else if (getProps().getKeyAlg().equals("DSA")) {
                sigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            } else if (getProps().getKeyAlg().equalsIgnoreCase(AlgorithmConstants.SIGALG_ED25519)) {
                sigAlg = AlgorithmConstants.SIGALG_ED25519;
            } else if (getProps().getKeyAlg().equalsIgnoreCase(AlgorithmConstants.SIGALG_ED448)) {
                sigAlg = AlgorithmConstants.SIGALG_ED448;
            } else if (getProps().getKeyAlg().equals(AlgorithmConstants.KEYALGORITHM_ECGOST3410)) {
                sigAlg = AlgorithmConstants.SIGALG_GOST3411_WITH_ECGOST3410;
            } else if (getProps().getKeyAlg().equals(AlgorithmConstants.KEYALGORITHM_DSTU4145)) {
                sigAlg = AlgorithmConstants.SIGALG_GOST3411_WITH_DSTU4145;
            }

            X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, keyPair.getPrivate(), keyPair.getPublic(), sigAlg, false);
            cert = (X509Certificate) EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class).createCertificate(getAuthenticationToken(),
                    username, password, selfcert);
        }

        // Make a certificate chain from the certificate and the CA-certificate
        Certificate[] cachain = EjbRemoteHelper.INSTANCE.getRemoteSession(SignSessionRemote.class).getCertificateChain(caId).toArray(new Certificate[0]);
        // Verify CA-certificate
        if (CertTools.isSelfSigned(cachain[cachain.length - 1])) {
            try {
                // Make sure we have BC certs, otherwise SHA256WithRSAAndMGF1
                // will not verify (at least not as of jdk6)
                Certificate cacert = CertTools.getCertfromByteArray(cachain[cachain.length - 1].getEncoded(), Certificate.class);
                cacert.verify(cacert.getPublicKey());
            } catch (GeneralSecurityException se) {
                String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorrootnotverify");
                throw new Exception(errMsg);
            }
        } else {
            String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorrootnotselfsigned");
            throw new Exception(errMsg);
        }

        // Verify that the user-certificate is signed by our CA
        try {
            // Make sure we have BC certs, otherwise SHA256WithRSAAndMGF1 will
            // not verify (at least not as of jdk6)
            Certificate cacert = CertTools.getCertfromByteArray(cachain[0].getEncoded(), Certificate.class);
            Certificate usercert = CertTools.getCertfromByteArray(cert.getEncoded(), Certificate.class);
            usercert.verify(cacert.getPublicKey());
        } catch (GeneralSecurityException se) {
            String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorgennotverify");
            throw new Exception(errMsg);
        }

        if (getUseKeyRecovery() && savekeys) {
            // Save generated keys to database.
            EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).addKeyRecoveryData(getAuthenticationToken(), EJBTools.wrap(cert), username,
                    EJBTools.wrap(keyPair));
        }

        // Use CN if as alias in the keystore, if CN is not present use username
        String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
        if (alias == null) {
            alias = username;
        }

        // Store keys and certificates in keystore.
        KeyStore ks = null;

        if (keystoreType == SecConst.TOKEN_SOFT_JKS) {
            ks = KeyTools.createJKS(alias, keyPair.getPrivate(), password, cert, cachain);
        } else if (keystoreType == SecConst.TOKEN_SOFT_BCFKS) {
            ks = KeyTools.createBcfks(alias, keyPair.getPrivate(), cert, cachain);
        } else {
            ks = KeyTools.createP12(alias, keyPair.getPrivate(), cert, cachain);
        }

        storeKeyStore(ks, username, password, keystoreType);
        String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.createkeystore", username);
        log.info(iMsg);
        if (log.isTraceEnabled()) {
            log.trace("<createUser: username=" + username);
        }
    }

    /**
     * Recovers or generates new keys for the user and generates keystore
     * 
     * @param data
     *            user data for user
     * @param keystoreType the type of keystore, one of the constants from {@link SecConst}
     * @param keyrecoverflag
     *            if we should try to revoer already existing keys
     * @throws Exception
     *             If something goes wrong...
     */
    private void processUser(EndEntityInformation data, int keystoreType, boolean keyrecoverflag) throws Exception {
        KeyPair rsaKeys = null;
        X509Certificate orgCert = null;
        if (getUseKeyRecovery() && keyrecoverflag) {
            boolean reusecertificate = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityProfileSessionRemote.class)
                    .getEndEntityProfile(data.getEndEntityProfileId()).getReUseKeyRecoveredCertificate();
            // Recover Keys

            KeyRecoveryInformation recoveryData = EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).recoverKeys(
                    getAuthenticationToken(), data.getUsername(), data.getEndEntityProfileId());
            if (reusecertificate) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(KeyRecoverySessionRemote.class).unmarkUser(getAuthenticationToken(), data.getUsername());
            }
            if (recoveryData != null) {
                rsaKeys = recoveryData.getKeyPair();
                if (reusecertificate) {
                    orgCert = (X509Certificate) recoveryData.getCertificate();
                }
            } else {
                String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errornokeyrecoverydata", data.getUsername());
                throw new Exception(errMsg);
            }
        } else {
            rsaKeys = KeyTools.genKeys(getProps().getKeySpec(), getProps().getKeyAlg());
        }
        // Get certificate for user and create keystore
        if (rsaKeys != null) {
            createKeysForUser(data.getUsername(), data.getPassword(), data.getCAId(), rsaKeys, keystoreType,
                    !keyrecoverflag && data.getKeyRecoverable(), orgCert);
        }
    }

    private boolean doCreateKeys(EndEntityInformation data, int status) throws Exception {
        boolean ret = false;
        // get users Token Type.
        int tokentype = data.getTokenType();
        boolean createJKS = (tokentype == SecConst.TOKEN_SOFT_JKS);
        boolean createPEM = (tokentype == SecConst.TOKEN_SOFT_PEM);
        boolean createP12 = tokentype == SecConst.TOKEN_SOFT_P12 || tokentype == SecConst.TOKEN_SOFT_BCFKS;
        // Only generate supported tokens
        if (createP12 || createPEM || createJKS) {
            if (status == EndEntityConstants.STATUS_KEYRECOVERY) {
                String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.retrieveingkeys", data.getUsername());
                log.info(iMsg);
            } else {
                String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generatingkeys", getProps().getKeyAlg(),
                        getProps().getKeySpec(), data.getUsername());
                log.info(iMsg);
            }
            processUser(data, tokentype, (status == EndEntityConstants.STATUS_KEYRECOVERY));
            // If all was OK, users status is set to GENERATED by the
            // signsession when the user certificate is created.
            // If status is still NEW, FAILED or KEYRECOVER though, it means we
            // should set it back to what it was before, probably it had a
            // request counter
            // meaning that we should not reset the clear text password yet.

            EndEntityInformation vo = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(
                    getAuthenticationToken(), data.getUsername());
            if ((vo.getStatus() == EndEntityConstants.STATUS_NEW) || (vo.getStatus() == EndEntityConstants.STATUS_FAILED)
                    || (vo.getStatus() == EndEntityConstants.STATUS_KEYRECOVERY)) {
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setClearTextPassword(getAuthenticationToken(),
                        data.getUsername(), data.getPassword());
            } else {
                // Delete clear text password, if we are not letting status be
                // the same as originally
                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setClearTextPassword(getAuthenticationToken(),
                        data.getUsername(), null);
            }
            ret = true;
            String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generateduser", data.getUsername());
            log.info(iMsg);
        } else {
            log.error("Cannot batchmake browser generated token for user (wrong tokentype)- " + data.getUsername());
        }
        return ret;
    }

    /**
     * Creates keystore-files for all users with status NEW in the local
     * database.
     */
    private void createAllNew()
            throws Exception {
        log.trace(">createAllNew");
        String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generatingallstatus", "NEW");
        log.info(iMsg);
        createAllWithStatus(EndEntityConstants.STATUS_NEW);
        log.trace("<createAllNew");
    }

    /**
     * Creates P12-files for all users with status FAILED in the local database.
     */
    private void createAllFailed()
            throws Exception {
        log.trace(">createAllFailed");
        String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generatingallstatus", "FAILED");
        log.info(iMsg);
        createAllWithStatus(EndEntityConstants.STATUS_FAILED);
        log.trace("<createAllFailed");
    }

    /**
     * Creates P12-files for all users with status KEYRECOVER in the local
     * database.
     */
    private void createAllKeyRecover()
            throws Exception {
        if (getUseKeyRecovery()) {
            log.trace(">createAllKeyRecover");
            String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generatingallstatus", "KEYRECOVER");
            log.info(iMsg);
            createAllWithStatus(EndEntityConstants.STATUS_KEYRECOVERY);
            log.trace("<createAllKeyRecover");
        }
    }

    /**
     * Creates P12-files for all users with status in the local database.
     * 
     * Since authentication tokens from the CLI are single use only, this method will take multiple (until a better design is reached).
     */
    private void createAllWithStatus(int status) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">createAllWithStatus: " + status);
        }
        CryptoProviderTools.installBCProviderIfNotAvailable(); // If this is invoked directly
        ArrayList<EndEntityInformation> result = new ArrayList<EndEntityInformation>();

        boolean stopnow = false;
        do {
            for (EndEntityInformation data : EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class)
                    .findAllBatchUsersByStatusWithLimit(status)) {
                if (data.getTokenType() == SecConst.TOKEN_SOFT_JKS || data.getTokenType() == SecConst.TOKEN_SOFT_PEM
                        || data.getTokenType() == SecConst.TOKEN_SOFT_P12) {
                    result.add(data);
                }
            }

            String iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.generatingnoofusers", Integer.valueOf(result.size()));
            log.info(iMsg);

            int failcount = 0;
            int successcount = 0;

            final GlobalConfigurationSessionRemote globalConfigurationSession = EjbRemoteHelper.INSTANCE.getRemoteSession(GlobalConfigurationSessionRemote.class);
            final GlobalCesecoreConfiguration globalConfiguration = (GlobalCesecoreConfiguration) globalConfigurationSession.getCachedConfiguration(GlobalCesecoreConfiguration.CESECORE_CONFIGURATION_ID);
            
            if (result.size() > 0) {
                if (result.size() < globalConfiguration.getMaximumQueryCount()) {
                    stopnow = true;
                }
                String failedusers = "";
                String successusers = "";
                for (EndEntityInformation data : result) {
                    if ((data.getPassword() != null) && (data.getPassword().length() > 0)) {
                        try {
                            if (doCreateKeys(data, status)) {
                                successusers += (":" + data.getUsername());
                                successcount++;
                            }
                        } catch (Exception e) {
                            // If things went wrong set status to FAILED
                            log.debug(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorsetstatus", "FAILED"), e);
                            failedusers += (":" + data.getUsername());
                            failcount++;
                            final String newStatusString;
                            if (status == EndEntityConstants.STATUS_KEYRECOVERY) {
                                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(
                                        getAuthenticationToken(), data.getUsername(), EndEntityConstants.STATUS_KEYRECOVERY);
                                newStatusString = "KEYRECOVERY";
                            } else {
                                EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(
                                        getAuthenticationToken(), data.getUsername(), EndEntityConstants.STATUS_FAILED);
                                newStatusString = "FAILED";
                            }
                            if (e instanceof IllegalKeyException) {
                                final String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfaileduser",
                                        data.getUsername());
                                log.error(errMsg + " " + e.getMessage());
                                log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorsetstatus", newStatusString));
                                log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorcheckconfig"));
                            } else {
                                log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorsetstatus", newStatusString), e);
                                final String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfaileduser",
                                        data.getUsername());
                                throw new Exception(errMsg, e);
                            }

                        }
                    } else {
                        iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.infonoclearpwd", data.getUsername());
                        log.info(iMsg);
                    }
                }

                if (failedusers.length() > 0) {
                    String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfailed", Integer.valueOf(failcount),
                            Integer.valueOf(successcount), failedusers);
                    log.error(errMsg);
                    throw new Exception(errMsg);
                }
                iMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.success", Integer.valueOf(successcount), successusers);
                log.info(iMsg);
            }
        } while ((result.size() > 0) && !stopnow);
        if (log.isTraceEnabled()) {
            log.trace("<createAllWithStatus: " + status);
        }
    }

    /**
     * Creates P12-files for one end entity in the local database.
     * 
     * @param username
     *            username
     * @throws Exception
     *             if the user does not exist or something goes wrong during
     *             generation
     */
    private void createKeysForUser(String username) throws Exception {
        if (log.isTraceEnabled()) {
            log.trace(">createUser(" + username + ")");
        }
        EndEntityInformation data = EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityAccessSessionRemote.class).findUser(getAuthenticationToken(),
                username);
        if (data == null) {
            log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorunknown", username));
            return;
        }
        int status = data.getStatus();
        if ((data != null) && (data.getPassword() != null) && (data.getPassword().length() > 0)) {
            if ((status == EndEntityConstants.STATUS_NEW) || ((status == EndEntityConstants.STATUS_KEYRECOVERY) && getUseKeyRecovery())) {
                try {
                    doCreateKeys(data, status);
                } catch (Exception e) {
                    // If things went wrong set status to FAILED
                    final String newStatusString;
                    if (status == EndEntityConstants.STATUS_KEYRECOVERY) {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAuthenticationToken(),
                                data.getUsername(), EndEntityConstants.STATUS_KEYRECOVERY);
                        newStatusString = "KEYRECOVERY";
                    } else {
                        EjbRemoteHelper.INSTANCE.getRemoteSession(EndEntityManagementSessionRemote.class).setUserStatus(getAuthenticationToken(),
                                data.getUsername(), EndEntityConstants.STATUS_FAILED);
                        newStatusString = "FAILED";
                    }
                    if (e instanceof IllegalKeyException) {
                        final String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfaileduser", username);
                        log.error(errMsg + " " + e.getMessage());
                        log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorsetstatus", newStatusString));
                        log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorcheckconfig"));
                    } else {
                        log.error(InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorsetstatus", newStatusString), e);
                        final String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfaileduser", username);
                        throw new Exception(errMsg);
                    }
                }
            } else {
                String errMsg = InternalEjbcaResources.getInstance().getLocalizedMessage("batch.errorbatchfaileduser", username);
                log.error(errMsg);
                throw new Exception(errMsg);
            }
        }
        if (log.isTraceEnabled()) {
            log.trace(">createUser(" + username + ")");
        }
    }

    /**
     * Return environment variable EJBCA_HOME or an empty string if the variable
     * isn't set.
     * 
     * @return Environment variable EJBCA_HOME
     */
    private static String getHomeDir() {
        String ejbcaHomeDir = System.getenv("EJBCA_HOME");
        if (ejbcaHomeDir == null) {
            ejbcaHomeDir = "";
        } else if (!ejbcaHomeDir.endsWith("/") && !ejbcaHomeDir.endsWith("\\")) {
            ejbcaHomeDir += File.separatorChar;
        }
        return ejbcaHomeDir;
    }

    @Override
    protected Logger getLogger() {
        return log;
    }

}
