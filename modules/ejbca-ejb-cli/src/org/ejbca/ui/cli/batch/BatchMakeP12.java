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

package org.ejbca.ui.cli.batch;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;

import org.ejbca.core.ejb.ca.auth.AuthenticationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.CAAdminSessionRemote;
import org.ejbca.core.ejb.ca.sign.SignSessionRemote;
import org.ejbca.core.ejb.keyrecovery.KeyRecoverySessionRemote;
import org.ejbca.core.ejb.ra.UserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.RaAdminSessionRemote;
import org.ejbca.core.model.AlgorithmConstants;
import org.ejbca.core.model.InternalResources;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.keyrecovery.KeyRecoveryData;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserAdminConstants;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.ui.cli.BaseCommand;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.util.CertTools;
import org.ejbca.util.CryptoProviderTools;
import org.ejbca.util.keystore.KeyTools;
import org.ejbca.util.keystore.P12toPEM;

/**
 * This class generates keys and request certificates for all users with status NEW. The result is
 * generated PKCS12, JKS or PEM-files.
 *
 * @version $Id$
 */
public class BatchMakeP12 extends BaseCommand {

    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    BatchToolProperties props = new BatchToolProperties();

    /**
     * Where created P12-files are stored, default p12
     */
    private String mainStoreDir = "";
    private final Admin admin = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);
    private Boolean usekeyrecovery = null;

    private AuthenticationSessionRemote authenticationSession = ejb.getAuthenticationSession();
    private CAAdminSessionRemote caAdminSession = ejb.getCAAdminSession();
    private KeyRecoverySessionRemote keyRecoverySession = ejb.getKeyRecoverySession();
    private RaAdminSessionRemote raAdminSession = ejb.getRAAdminSession();
    private SignSessionRemote signSession = ejb.getSignSession();
    private UserAdminSessionRemote userAdminSession = ejb.getUserAdminSession();

    public String getMainCommand() {
        return null;
    }

    public String getSubCommand() {
        return "batch";
    }

    public String getDescription() {
        return "Generate keys and certificates for all users with status NEW";
    }

    public void execute(String[] args) throws ErrorAdminCommandException {
        try {
            String username = null;
            String directory = getHomeDir() + "p12";
            for (int i = 1; i < args.length; i++) {
                if ("-?".equalsIgnoreCase(args[i]) || "--help".equalsIgnoreCase(args[i])) {
                    getLogger().info("Description: " + getDescription());
                    getLogger().info("Usage: " + getCommand() + " [username] [-dir directory]");
                    getLogger().info("   username: the name of the user to generate the key.");
                    getLogger().info("             If omitted, keys will be generated for all users with status NEW or FAILED");
                    getLogger().info("   directory: the name of the directory to store the keys to");
                    System.exit(1); // NOPMD
                } else if ("-dir".equalsIgnoreCase(args[i])) {
                    directory = args[++i];
                } else {
                    username = args[i];
                }
            }
            if (username == null) {
                getLogger().info("Use '" + getSubCommand() + " --help' for additional options.");
            }
            // Bouncy Castle security provider
            CryptoProviderTools.installBCProviderIfNotAvailable();
            // Create subdirectory 'p12' if it does not exist
            File dir = new File(directory).getCanonicalFile();
            dir.mkdir();
            setMainStoreDir(directory);
            String iMsg = intres.getLocalizedMessage("batch.generateindir", dir);
            getLogger().info(iMsg);

            if (username != null) {
                createUser(username);
            } else {
                // Make P12 for all NEW users in local DB
                createAllNew();
                // Make P12 for all FAILED users in local DB
                createAllFailed();
                // Make P12 for all KEYRECOVERABLE users in local DB
                createAllKeyRecover();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1); // NOPMD
        }
    }

    protected Admin getAdmin() {
        return admin;
    }

    private boolean getUseKeyRecovery() throws RemoteException {
        if (usekeyrecovery == null) {
            usekeyrecovery = (raAdminSession.loadGlobalConfiguration(getAdmin())).getEnableKeyRecovery();
        }
        return usekeyrecovery;
    }

    /**
     * Gets full CA-certificate chain.
     * 
     * @return Certificate[]
     */
    private Certificate[] getCACertChain(int caid) throws Exception {
        getLogger().trace(">getCACertChain()");
        Certificate[] chain = (Certificate[]) signSession.getCertificateChain(getAdmin(), caid).toArray(new Certificate[0]);
        getLogger().trace("<getCACertChain()");
        return chain;
    }

    /**
     * Sets the location where generated P12-files will be stored, full name
     * will be: mainStoreDir/username.p12.
     * 
     * @param dir
     *            existing directory
     */
    public void setMainStoreDir(String dir) {
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
     * @param createJKS
     *            if a jks should be created
     * @param createPEM
     *            if pem files should be created
     * @throws IOException
     *             if directory to store keystore cannot be created
     */
    private void storeKeyStore(KeyStore ks, String username, String kspassword, boolean createJKS, boolean createPEM) throws IOException, KeyStoreException,
            UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        if (getLogger().isTraceEnabled()) {
            getLogger().trace(">storeKeyStore: ks=" + ks.toString() + ", username=" + username);
        }
        // Where to store it?
        if (mainStoreDir == null) {
            throw new IOException("Can't find directory to store keystore in.");
        }

        if (!new File(mainStoreDir).exists()) {
            new File(mainStoreDir).mkdir();
            getLogger().info("Directory '" + mainStoreDir + "' did not exist and was created.");
        }

        String keyStoreFilename = mainStoreDir + "/" + username;

        if (createJKS) {
            keyStoreFilename += ".jks";
        } else {
            keyStoreFilename += ".p12";
        }

        // If we should also create PEM-files, do that
        if (createPEM) {
            String PEMfilename = mainStoreDir + "/pem";
            P12toPEM p12topem = new P12toPEM(ks, kspassword, true);
            p12topem.setExportPath(PEMfilename);
            p12topem.createPEM();
        } else {
            FileOutputStream os = new FileOutputStream(keyStoreFilename);
            ks.store(os, kspassword.toCharArray());
        }

        getLogger().debug("Keystore stored in " + keyStoreFilename);
        if (getLogger().isTraceEnabled()) {
            getLogger().trace("<storeKeyStore: ks=" + ks.toString() + ", username=" + username);
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
     * @param id
     *            of CA used to issue the keystore certificates
     * @param rsaKeys
     *            a previously generated RSA keypair
     * @param createJKS
     *            if a jks should be created
     * @param createPEM
     *            if pem files should be created
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

    private void createUser(String username, String password, int caid, KeyPair rsaKeys, boolean createJKS, boolean createPEM, boolean savekeys,
            X509Certificate orgCert) throws Exception {
        if (getLogger().isTraceEnabled()) {
            getLogger().trace(">createUser: username=" + username);
        }

        X509Certificate cert = null;

        if (orgCert != null) {
            cert = orgCert;
            boolean finishUser = caAdminSession.getCAInfo(getAdmin(), caid).getFinishUser();
            if (finishUser) {
                authenticationSession.finishUser(getAdmin(), username, password);
            }

        } else {
            // Create self signed certificate, because ECDSA keys are not
            // serializable
            String sigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_RSA;
            if (props.getKeyAlg().equals("ECDSA")) {
                sigAlg = AlgorithmConstants.SIGALG_SHA256_WITH_ECDSA;
            } else if (props.getKeyAlg().equals("DSA")) {
                sigAlg = AlgorithmConstants.SIGALG_SHA1_WITH_DSA;
            }

            X509Certificate selfcert = CertTools.genSelfCert("CN=selfsigned", 1, null, rsaKeys.getPrivate(), rsaKeys.getPublic(), sigAlg, false);
            cert = (X509Certificate) signSession.createCertificate(getAdmin(), username, password, selfcert);
        }

        // System.out.println("issuer " + CertTools.getIssuerDN(cert) + ", " +
        // cert.getClass().getName());
        // Make a certificate chain from the certificate and the CA-certificate
        Certificate[] cachain = getCACertChain(caid);
        // Verify CA-certificate
        if (CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
            try {
                // Make sure we have BC certs, otherwise SHA256WithRSAAndMGF1
                // will not verify (at least not as of jdk6)
                Certificate cacert = CertTools.getCertfromByteArray(cachain[cachain.length - 1].getEncoded());
                cacert.verify(cacert.getPublicKey());
                // cachain[cachain.length - 1].verify(cachain[cachain.length -
                // 1].getPublicKey());
            } catch (GeneralSecurityException se) {
                String errMsg = intres.getLocalizedMessage("batch.errorrootnotverify");
                throw new Exception(errMsg);
            }
        } else {
            String errMsg = intres.getLocalizedMessage("batch.errorrootnotselfsigned");
            throw new Exception(errMsg);
        }

        // Verify that the user-certificate is signed by our CA
        try {
            // Make sure we have BC certs, otherwise SHA256WithRSAAndMGF1 will
            // not verify (at least not as of jdk6)
            Certificate cacert = CertTools.getCertfromByteArray(cachain[0].getEncoded());
            Certificate usercert = CertTools.getCertfromByteArray(cert.getEncoded());
            usercert.verify(cacert.getPublicKey());
        } catch (GeneralSecurityException se) {
            String errMsg = intres.getLocalizedMessage("batch.errorgennotverify");
            throw new Exception(errMsg);
        }

        if (getUseKeyRecovery() && savekeys) {
            // Save generated keys to database.
            keyRecoverySession.addKeyRecoveryData(getAdmin(), cert, username, rsaKeys);
        }

        // Use CN if as alias in the keystore, if CN is not present use username
        String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
        if (alias == null) {
            alias = username;
        }

        // Store keys and certificates in keystore.
        KeyStore ks = null;

        if (createJKS) {
            ks = KeyTools.createJKS(alias, rsaKeys.getPrivate(), password, cert, cachain);
        } else {
            ks = KeyTools.createP12(alias, rsaKeys.getPrivate(), cert, cachain);
        }

        storeKeyStore(ks, username, password, createJKS, createPEM);
        String iMsg = intres.getLocalizedMessage("batch.createkeystore", username);
        getLogger().info(iMsg);
        if (getLogger().isTraceEnabled()) {
            getLogger().trace("<createUser: username=" + username);
        }
    }

    /**
     * Recovers or generates new keys for the user and generates keystore
     * 
     * @param data
     *            user data for user
     * @param createJKS
     *            if a jks should be created
     * @param createPEM
     *            if pem files should be created
     * @param keyrecoverflag
     *            if we should try to revoer already existing keys
     * @throws Exception
     *             If something goes wrong...
     */
    private void processUser(UserDataVO data, boolean createJKS, boolean createPEM, boolean keyrecoverflag) throws Exception {
        KeyPair rsaKeys = null;
        X509Certificate orgCert = null;
        if (getUseKeyRecovery() && keyrecoverflag) {
            boolean reusecertificate = raAdminSession.getEndEntityProfile(getAdmin(), data.getEndEntityProfileId()).getReUseKeyRevoceredCertificate();
            // Recover Keys

            KeyRecoveryData recoveryData = keyRecoverySession.keyRecovery(getAdmin(), data.getUsername(), data.getEndEntityProfileId());
            if (reusecertificate) {
                keyRecoverySession.unmarkUser(getAdmin(), data.getUsername());
            }
            if (recoveryData != null) {
                rsaKeys = recoveryData.getKeyPair();
                if (reusecertificate) {
                    orgCert = (X509Certificate) recoveryData.getCertificate();
                }
            } else {
                String errMsg = intres.getLocalizedMessage("batch.errornokeyrecoverydata", data.getUsername());
                throw new Exception(errMsg);
            }
        } else {
            rsaKeys = KeyTools.genKeys(props.getKeySpec(), props.getKeyAlg());
        }
        // Get certificate for user and create keystore
        if (rsaKeys != null) {
            createUser(data.getUsername(), data.getPassword(), data.getCAId(), rsaKeys, createJKS, createPEM, !keyrecoverflag && data.getKeyRecoverable(),
                    orgCert);
        }
    }

    private boolean doCreate(UserDataVO data, int status) throws Exception {
        boolean ret = false;
        // get users Token Type.
        int tokentype = data.getTokenType();
        boolean createJKS = (tokentype == SecConst.TOKEN_SOFT_JKS);
        boolean createPEM = (tokentype == SecConst.TOKEN_SOFT_PEM);
        boolean createP12 = (tokentype == SecConst.TOKEN_SOFT_P12);
        // Only generate supported tokens
        if (createP12 || createPEM || createJKS) {
            if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                String iMsg = intres.getLocalizedMessage("batch.retrieveingkeys", data.getUsername());
                getLogger().info(iMsg);
            } else {
                String iMsg = intres.getLocalizedMessage("batch.generatingkeys", data.getUsername());
                getLogger().info(iMsg);
            }
            processUser(data, createJKS, createPEM, (status == UserDataConstants.STATUS_KEYRECOVERY));
            // If all was OK, users status is set to GENERATED by the
            // signsession when the user certificate is created.
            // If status is still NEW, FAILED or KEYRECOVER though, it means we
            // should set it back to what it was before, probably it had a
            // request counter
            // meaning that we should not reset the clear text password yet.

            UserDataVO vo = userAdminSession.findUser(getAdmin(), data.getUsername());
            if ((vo.getStatus() == UserDataConstants.STATUS_NEW) || (vo.getStatus() == UserDataConstants.STATUS_FAILED)
                    || (vo.getStatus() == UserDataConstants.STATUS_KEYRECOVERY)) {
                userAdminSession.setClearTextPassword(getAdmin(), data.getUsername(), data.getPassword());
            } else {
                // Delete clear text password, if we are not letting status be
                // the same as originally
                userAdminSession.setClearTextPassword(getAdmin(), data.getUsername(), null);
            }
            ret = true;
            String iMsg = intres.getLocalizedMessage("batch.generateduser", data.getUsername());
            getLogger().info(iMsg);
        } else {
            getLogger().debug("Cannot batchmake browser generated token for user (wrong tokentype)- " + data.getUsername());
        }
        return ret;
    }

    /**
     * Creates keystore-files for all users with status NEW in the local
     * database.
     * 
     * @throws Exception
     *             if something goes wrong...
     */
    public void createAllNew() throws Exception {
        getLogger().trace(">createAllNew");
        String iMsg = intres.getLocalizedMessage("batch.generatingallstatus", "NEW");
        getLogger().info(iMsg);
        createAllWithStatus(UserDataConstants.STATUS_NEW);
        getLogger().trace("<createAllNew");
    }

    /**
     * Creates P12-files for all users with status FAILED in the local database.
     * 
     * @throws Exception
     *             if something goes wrong...
     */
    public void createAllFailed() throws Exception {
        getLogger().trace(">createAllFailed");
        String iMsg = intres.getLocalizedMessage("batch.generatingallstatus", "FAILED");
        getLogger().info(iMsg);
        createAllWithStatus(UserDataConstants.STATUS_FAILED);
        getLogger().trace("<createAllFailed");
    }

    /**
     * Creates P12-files for all users with status KEYRECOVER in the local
     * database.
     * 
     * @throws Exception
     *             if something goes wrong...
     */
    public void createAllKeyRecover() throws Exception {
        if (getUseKeyRecovery()) {
            getLogger().trace(">createAllKeyRecover");
            String iMsg = intres.getLocalizedMessage("batch.generatingallstatus", "KEYRECOVER");
            getLogger().info(iMsg);
            createAllWithStatus(UserDataConstants.STATUS_KEYRECOVERY);
            getLogger().trace("<createAllKeyRecover");
        }
    }

    /**
     * Creates P12-files for all users with status in the local database.
     * 
     * @param status
     * @throws Exception
     *             if something goes wrong...
     */
    public void createAllWithStatus(int status) throws Exception {
        if (getLogger().isTraceEnabled()) {
            getLogger().trace(">createAllWithStatus: " + status);
        }
        CertTools.installBCProviderIfNotAvailable(); // If this is invoked
                                                     // directly
        ArrayList result;

        boolean stopnow = false;
        do {
            Collection queryResult = userAdminSession.findAllUsersByStatusWithLimit(getAdmin(), status, true);
            result = new ArrayList();
            Iterator iter = queryResult.iterator();
            while (iter.hasNext()) {
                UserDataVO data = (UserDataVO) iter.next();
                if (data.getTokenType() == SecConst.TOKEN_SOFT_JKS || data.getTokenType() == SecConst.TOKEN_SOFT_PEM
                        || data.getTokenType() == SecConst.TOKEN_SOFT_P12) {
                    result.add(data);
                }
            }
            String iMsg = intres.getLocalizedMessage("batch.generatingnoofusers", new Integer(result.size()));
            getLogger().info(iMsg);

            int failcount = 0;
            int successcount = 0;

            if (result.size() > 0) {
                if (result.size() < UserAdminConstants.MAXIMUM_QUERY_ROWCOUNT) {
                    stopnow = true;
                }
                Iterator it = result.iterator();
                String failedusers = "";
                String successusers = "";
                while (it.hasNext()) {
                    UserDataVO data = (UserDataVO) it.next();
                    if ((data.getPassword() != null) && (data.getPassword().length() > 0)) {
                        try {
                            if (doCreate(data, status)) {
                                successusers += (":" + data.getUsername());
                                successcount++;
                            }
                        } catch (Exception e) {
                            // If things went wrong set status to FAILED
                            String errMsg = intres.getLocalizedMessage("batch.errorsetstatus", "FAILED");
                            getLogger().error(errMsg, e);
                            getLogger().debug("batch.errorsetstatus", e);
                            failedusers += (":" + data.getUsername());
                            failcount++;
                            if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                                userAdminSession.setUserStatus(getAdmin(), data.getUsername(), UserDataConstants.STATUS_KEYRECOVERY);
                            } else {
                                userAdminSession.setUserStatus(getAdmin(), data.getUsername(), UserDataConstants.STATUS_FAILED);
                            }
                        }
                    } else {
                        iMsg = intres.getLocalizedMessage("batch.infonoclearpwd", data.getUsername());
                        getLogger().info(iMsg);
                    }
                }

                if (failedusers.length() > 0) {
                    String errMsg = intres.getLocalizedMessage("batch.errorbatchfailed", new Integer(failcount), new Integer(successcount), failedusers);
                    throw new Exception(errMsg);
                }

                iMsg = intres.getLocalizedMessage("batch.success", new Integer(successcount), successusers);
                getLogger().info(iMsg);
            }
        } while ((result.size() > 0) && !stopnow);
        if (getLogger().isTraceEnabled()) {
            getLogger().trace("<createAllWithStatus: " + status);
        }
    }

    /**
     * Creates P12-files for one user in the local database.
     * 
     * @param username
     *            username
     * @throws Exception
     *             if the user does not exist or something goes wrong during
     *             generation
     */
    public void createUser(String username) throws Exception {
        if (getLogger().isTraceEnabled()) {
            getLogger().trace(">createUser(" + username + ")");
        }
        UserDataVO data = userAdminSession.findUser(getAdmin(), username);
        if (data == null) {
            getLogger().error(intres.getLocalizedMessage("batch.errorunknown", username));
            return;
        }
        int status = data.getStatus();

        if ((data != null) && (data.getPassword() != null) && (data.getPassword().length() > 0)) {
            if ((status == UserDataConstants.STATUS_NEW) || ((status == UserDataConstants.STATUS_KEYRECOVERY) && getUseKeyRecovery())) {
                try {
                    doCreate(data, status);
                } catch (Exception e) {
                    // If things went wrong set status to FAILED
                    String errMsg = intres.getLocalizedMessage("batch.errorsetstatus", "FAILED");
                    getLogger().error(errMsg, e);
                    if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                        userAdminSession.setUserStatus(getAdmin(), data.getUsername(), UserDataConstants.STATUS_KEYRECOVERY);
                    } else {
                        userAdminSession.setUserStatus(getAdmin(), data.getUsername(), UserDataConstants.STATUS_FAILED);
                    }
                    errMsg = intres.getLocalizedMessage("batch.errorbatchfaileduser", username);
                    throw new Exception(errMsg);
                }
            } else {
                String errMsg = intres.getLocalizedMessage("batch.errorbatchfaileduser", username);
                getLogger().error(errMsg);
                throw new Exception(errMsg);
            }
        }
        if (getLogger().isTraceEnabled()) {
            getLogger().trace(">createUser(" + username + ")");
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
}
