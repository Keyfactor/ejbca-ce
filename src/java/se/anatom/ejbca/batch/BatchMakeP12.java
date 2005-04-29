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

package se.anatom.ejbca.batch;

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
import java.util.Collection;
import java.util.Iterator;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.common.UserDataVO;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote;
import se.anatom.ejbca.keyrecovery.KeyRecoveryData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminConstants;
import se.anatom.ejbca.ra.UserDataConstants;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.InitialContextBuilder;
import se.anatom.ejbca.util.KeyTools;
import se.anatom.ejbca.util.P12toPEM;


/**
 * This class generates keys and request certificates for all users with status NEW. The result is
 * generated PKCS12-files.
 *
 * @version $Id: BatchMakeP12.java,v 1.56 2005-04-29 08:16:31 anatom Exp $
 */
public class BatchMakeP12 {
    /**
     * For logging
     */
    private static final Logger log = Logger.getLogger(BatchMakeP12.class);


    /**
     * Where created P12-files are stored, default username.p12
     */
    private String mainStoreDir = "";
    private IUserAdminSessionHome adminhome;
    private IRaAdminSessionHome raadminhome;
    private ISignSessionHome signhome;
    private IKeyRecoverySessionHome keyrecoveryhome;
    private Admin administrator;
    private boolean usekeyrecovery = false;

    /**
     * Gets an initial context
     *
     * @return new initial context
     * @throws NamingException if we can't find jndi name
     */
    public static Context getInitialContext() throws NamingException {
        log.debug(">GetInitialContext");

        // jndi.properties must exist in classpath
        Context ctx = InitialContextBuilder.getInstance().getInitialContext();
        log.debug("<GetInitialContext");

        return ctx;
    }

    /**
     * Creates new BatchMakeP12 object.
     *
     * @throws javax.naming.NamingException
     * @throws CreateException
     * @throws RemoteException
     */
    public BatchMakeP12()
            throws javax.naming.NamingException, javax.ejb.CreateException, java.rmi.RemoteException,
            java.io.IOException {
        log.debug(">BatchMakeP12:");
        administrator = new Admin(Admin.TYPE_BATCHCOMMANDLINE_USER);

        // Bouncy Castle security provider
        CertTools.installBCProvider();

        Context jndiContext = getInitialContext();
        Object obj = jndiContext.lookup("UserAdminSession");
        adminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        obj = jndiContext.lookup("RaAdminSession");
        raadminhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IRaAdminSessionHome.class);
        obj = jndiContext.lookup("RSASignSession");
        signhome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, ISignSessionHome.class);

        IRaAdminSessionRemote raadmin = raadminhome.create();
        usekeyrecovery = (raadmin.loadGlobalConfiguration(administrator)).getEnableKeyRecovery();

        if (usekeyrecovery) {
            obj = jndiContext.lookup("KeyRecoverySession");
            keyrecoveryhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IKeyRecoverySessionHome.class);
        }


        log.debug("<BatchMakeP12:");
    } // BatchMakeP12

    /**
     * Gets full CA-certificate chain.
     *
     * @return Certificate[]
     */
    private Certificate[] getCACertChain(int caid)
            throws Exception {
        log.debug(">getCACertChain()");

        ISignSessionRemote ss = signhome.create();
        Certificate[] chain = (Certificate[]) ss.getCertificateChain(administrator, caid).toArray(new Certificate[0]);
        log.debug("<getCACertChain()");

        return chain;
    } // getCACertificate

    /**
     * Sets the location where generated P12-files will be stored, full name will be:
     * mainStoreDir/username.p12.
     *
     * @param dir existing directory
     */
    public void setMainStoreDir(String dir) {
        mainStoreDir = dir;
    }

    /**
     * Stores keystore.
     *
     * @param ks         KeyStore
     * @param username   username, the owner of the keystore
     * @param kspassword the password used to protect the peystore
     * @param createJKS  if a jks should be created
     * @param createPEM  if pem files should be created
     * @throws IOException if directory to store keystore cannot be created
     */
    private void storeKeyStore(KeyStore ks, String username, String kspassword, boolean createJKS,
                               boolean createPEM)
            throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException,
            NoSuchProviderException, CertificateException {
        log.debug(">storeKeyStore: ks=" + ks.toString() + ", username=" + username);

        // Where to store it?
        if (mainStoreDir == null) {
            throw new IOException("Can't find directory to store keystore in.");
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

        log.debug("Keystore stored in " + keyStoreFilename);
        log.debug("<storeKeyStore: ks=" + ks.toString() + ", username=" + username);
    } // storeKeyStore

    /**
     * Creates files for a user, sends request to CA, receives reploy and creates P12.
     *
     * @param username  username
     * @param password  user's password
     * @param id        of CA used to issue the keystore certificates
     * @param rsaKeys   a previously generated RSA keypair
     * @param createJKS if a jks should be created
     * @param createPEM if pem files should be created
     * @param savekeys  if generated keys should be saved in db (key recovery)
     * @throws Exception if the certificate is not an X509 certificate
     * @throws Exception if the CA-certificate is corrupt
     * @throws Exception if verification of certificate or CA-cert fails
     * @throws Exception if keyfile (generated by ourselves) is corrupt
     */

    private void createUser(String username, String password, int caid, KeyPair rsaKeys, boolean createJKS, boolean createPEM, boolean savekeys)
            throws Exception {
        log.debug(">createUser: username=" + username);

        // Send the certificate request to the CA
        ISignSessionRemote ss = signhome.create();
        X509Certificate cert = (X509Certificate) ss.createCertificate(administrator, username,
                password, rsaKeys.getPublic());

        //System.out.println("issuer " + CertTools.getIssuerDN(cert) + ", " + cert.getClass().getName());
        // Make a certificate chain from the certificate and the CA-certificate
        Certificate[] cachain = getCACertChain(caid);
        // Verify CA-certificate
        if (CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
            try {
                cachain[cachain.length - 1].verify(cachain[cachain.length - 1].getPublicKey());
            } catch (GeneralSecurityException se) {
                throw new Exception("RootCA certificate does not verify");
            }
        } else {
            throw new Exception("RootCA certificate not self-signed");
        }

        // Verify that the user-certificate is signed by our CA
        try {
            cert.verify(cachain[0].getPublicKey());
        } catch (GeneralSecurityException se) {
            throw new Exception("Generated certificate does not verify using CA-certificate.");
        }

        if (usekeyrecovery && savekeys) {
            // Save generated keys to database.
            IKeyRecoverySessionRemote keyrecoverysession = keyrecoveryhome.create();
            keyrecoverysession.addKeyRecoveryData(administrator, cert, username, rsaKeys);
        }

        // Use CN if as alias in the keystore, if CN is not present use username
        String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
        if (alias == null) alias = username;

        // Store keys and certificates in keystore.
        KeyStore ks = null;

        if (createJKS) {
            ks = KeyTools.createJKS(alias, rsaKeys.getPrivate(), password, cert, cachain);
        } else {
            ks = KeyTools.createP12(alias, rsaKeys.getPrivate(), cert, cachain);
        }

        storeKeyStore(ks, username, password, createJKS, createPEM);
        log.info("Created Keystore for " + username + ".");
        log.debug("<createUser: username=" + username);
    } // createUser

    /**
     * Does the deed with one user...
     *
     * @param data           user data for user
     * @param createJKS      if a jks should be created
     * @param createPEM      if pem files should be created
     * @param keyrecoverflag if we should try to revoer already existing keys
     * @throws Exception If something goes wrong...
     */
    private void processUser(UserDataVO data, boolean createJKS, boolean createPEM,
                             boolean keyrecoverflag) throws Exception {
        KeyPair rsaKeys = null;

        if (usekeyrecovery && keyrecoverflag) {
            // Recover Keys
            IKeyRecoverySessionRemote keyrecoverysession = keyrecoveryhome.create();
            KeyRecoveryData recoveryData = keyrecoverysession.keyRecovery(administrator, data.getUsername());
            if (recoveryData != null) {
                rsaKeys = recoveryData.getKeyPair();
            } else {
                throw new Exception("No Key Recovery Data available for user, " + data.getUsername() + " can not be generated.");
            }
        } else {
            rsaKeys = KeyTools.genKeys(1024);
        }
        // Get certificate for user and create P12
        if (rsaKeys != null) {
            createUser(data.getUsername(), data.getPassword(), data.getCAId(), rsaKeys, createJKS, createPEM, data.getKeyRecoverable());
        }
    } //processUser

    private boolean doCreate(IUserAdminSessionRemote admin, UserDataVO data, int status) throws Exception {
        boolean ret = false;
        int tokentype = SecConst.TOKEN_SOFT_BROWSERGEN;
        boolean createJKS = false;
        boolean createPEM = false;
        boolean createP12 = false;
        // get users Token Type.
        tokentype = data.getTokenType();
        createP12 = tokentype == SecConst.TOKEN_SOFT_P12;
        createPEM = tokentype == SecConst.TOKEN_SOFT_PEM;
        createJKS = tokentype == SecConst.TOKEN_SOFT_JKS;
        
        // Only generate supported tokens
        if (createP12 || createPEM || createJKS) {
            if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                log.info("Retrieving keys for " + data.getUsername());
            } else {
                log.info("Generating keys for " + data.getUsername());
            }                               
            
            // Grab new user, set status to INPROCESS
            admin.setUserStatus(administrator, data.getUsername(),
                    UserDataConstants.STATUS_INPROCESS);
            processUser(data, createJKS, createPEM,
                    (status == UserDataConstants.STATUS_KEYRECOVERY));
            
            // If all was OK , set status to GENERATED
            admin.setUserStatus(administrator, data.getUsername(),
                    UserDataConstants.STATUS_GENERATED);
            
            // Delete clear text password
            admin.setClearTextPassword(administrator, data.getUsername(), null);
            ret = true;
            log.info("New user generated successfully - " + data.getUsername());
        } else {
            log.debug("Cannot batchmake browser generated token for user (wrong tokentype)- " +
                    data.getUsername());
        }        
        return ret;
    }
    
    /**
     * Creates P12-files for all users with status NEW in the local database.
     *
     * @throws Exception if something goes wrong...
     */
    public void createAllNew() throws Exception {
        log.debug(">createAllNew:");
        log.info("Generating for all NEW.");
        createAllWithStatus(UserDataConstants.STATUS_NEW);
        log.debug("<createAllNew:");
    } // createAllNew

    /**
     * Creates P12-files for all users with status FAILED in the local database.
     *
     * @throws Exception if something goes wrong...
     */
    public void createAllFailed() throws Exception {
        log.debug(">createAllFailed:");
        log.info("Generating for all FAILED.");
        createAllWithStatus(UserDataConstants.STATUS_FAILED);
        log.debug("<createAllFailed:");
    } // createAllFailed

    /**
     * Creates P12-files for all users with status KEYRECOVER in the local database.
     *
     * @throws Exception if something goes wrong...
     */
    public void createAllKeyRecover() throws Exception {
        if (usekeyrecovery) {
            log.debug(">createAllKeyRecover:");
            log.info("Generating for all KEYRECOVER.");
            createAllWithStatus(UserDataConstants.STATUS_KEYRECOVERY);
            log.debug("<createAllKeyRecover:");
        }
    } // createAllKeyRecover

    /**
     * Creates P12-files for all users with status in the local database.
     *
     * @param status
     * @throws Exception if something goes wrong...
     */
    public void createAllWithStatus(int status) throws Exception {
        log.debug(">createAllWithStatus: " + status);

        Collection result;
        IUserAdminSessionRemote admin = adminhome.create();
        boolean stopnow = false;

        //Collection result = admin.findAllUsersByStatus(administrator, status);
        do {
            result = admin.findAllUsersByStatusWithLimit(administrator, status, true);
            log.info("Batch generating " + result.size() + " users.");

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
                            if (doCreate(admin, data, status)) {
                                successusers += (":" + data.getUsername());
                                successcount++;
                            }
                        } catch (Exception e) {
                            // If things went wrong set status to FAILED
                            log.error("An error happened, setting status to FAILED.", e);
                            failedusers += (":" + data.getUsername());
                            failcount++;
                            if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                                admin.setUserStatus(administrator, data.getUsername(), UserDataConstants.STATUS_KEYRECOVERY);
                            } else {
                                admin.setUserStatus(administrator, data.getUsername(), UserDataConstants.STATUS_FAILED);
                            }
                        }
                    } else {
                        log.debug("User '" + data.getUsername() +
                                "' does not have clear text password.");
                    }
                }

                if (failedusers.length() > 0) {
                    throw new Exception("BatchMakeP12 failed for " + failcount + " users (" +
                            successcount + " succeeded) - " + failedusers);
                }

                log.info(successcount + " new users generated successfully - " + successusers);
            }
        } while ((result.size() > 0) && !stopnow);

        log.debug("<createAllWithStatus: " + status);
    } // createAllWithStatus

    /**
     * Creates P12-files for one user in the local database.
     *
     * @param username username
     * @throws Exception if the user does not exist or something goes wrong during generation
     */
    public void createUser(String username) throws Exception {
        log.debug(">createUser(" + username + ")");

        IUserAdminSessionRemote admin = adminhome.create();
        UserDataVO data = admin.findUser(administrator, username);
        int status = data.getStatus();

        if ((data != null) && (data.getPassword() != null) && (data.getPassword().length() > 0)) {
            if ((status == UserDataConstants.STATUS_NEW) ||
                    ((status == UserDataConstants.STATUS_KEYRECOVERY) && usekeyrecovery)) {
                try {
                    doCreate(admin, data, status);
                } catch (Exception e) {
                    // If things went wrong set status to FAILED
                    log.error("An error happened, setting status to FAILED (if not keyrecovery).");
                    log.error(e);
                    if (status == UserDataConstants.STATUS_KEYRECOVERY) {
                        admin.setUserStatus(administrator, data.getUsername(), UserDataConstants.STATUS_KEYRECOVERY);
                    } else {
                        admin.setUserStatus(administrator, data.getUsername(), UserDataConstants.STATUS_FAILED);
                    }
                    throw new Exception("BatchMakeP12 failed for '" + username + "'.");
                }
            } else {
                log.error("Unknown user, or clear text password is null: " + username);
                throw new Exception("BatchMakeP12 failed for '" + username + "'.");
            }
        }

        log.debug(">createUser(" + username + ")");
    } // doit

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            BatchMakeP12 makep12 = new BatchMakeP12();
            String username = null;
            String directory = "p12";
            for (int i = 0; i < args.length; i++) {
                if ("-?".equalsIgnoreCase(args[i]) || "--help".equalsIgnoreCase(args[i])){
                    System.out.println("Usage: batch [username] [-dir directory]");
                    System.out.println("   username: the name of the user to generate the key.");
                    System.out.println("             If omitted, keys will be generated for all users with status NEW or FAILED");
                    System.out.println("   directory: the name of the directory to store the keys to");
                    System.exit(1);
                } else if ("-dir".equalsIgnoreCase(args[i])){
                    directory = args[++i];
                } else {
                    username = args[i];
                }
            }

            // Create subdirectory 'p12' if it does not exist
            File dir = new File(directory).getCanonicalFile();
            dir.mkdir();
            makep12.setMainStoreDir(directory);
            log.info("Generating keys in directory " + dir);

            if (username != null) {
                makep12.createUser(username);
            } else {
                // Make P12 for all NEW users in local DB
                makep12.createAllNew();

                // Make P12 for all FAILED users in local DB
                makep12.createAllFailed();

                // Make P12 for all KEYRECOVERABLE users in local DB
                makep12.createAllKeyRecover();
            }
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    } // main

} // BatchMakeP12
