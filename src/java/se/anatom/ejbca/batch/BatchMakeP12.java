package se.anatom.ejbca.batch;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.*;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.Context;
import javax.naming.NamingException;

import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

import org.bouncycastle.jce.provider.*;


import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote;
import se.anatom.ejbca.keyrecovery.KeyRecoveryData;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSessionRemote;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserDataLocal;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;
import se.anatom.ejbca.util.P12toPEM;


/**
 * This class generates keys and request certificates for all users with status NEW. The result is
 * generated PKCS12-files.
 *
 * @version $Id: BatchMakeP12.java,v 1.44 2003-11-20 15:23:22 anatom Exp $
 */
public class BatchMakeP12 {
    /** For logging */
    private static Logger log = Logger.getLogger(BatchMakeP12.class);



    /** Where created P12-files are stored, default username.p12 */
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
     *
     * @throws NamingException if we can't find jndi name
     */
    public static Context getInitialContext() throws NamingException {
        log.debug(">GetInitialContext");

        // jndi.properties must exist in classpath
        Context ctx = new javax.naming.InitialContext();
        log.debug("<GetInitialContext");

        return ctx;
    }

    /**
     * Creates new BatchMakeP12 object.
     *
     * @exception javax.naming.NamingException
     * @exception CreateException
     * @exception RemoteException
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

        if(usekeyrecovery){
          obj = jndiContext.lookup("KeyRecoverySession");
          keyrecoveryhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IKeyRecoverySessionHome.class);
        }
  

       
        log.debug("<BatchMakeP12:");
    }

    // BatchMakeP12

    /**
     * Gets CA-certificate(s).
     *
     * @return X509Certificate
     */
    private X509Certificate getCACertificate(int caid)
      throws Exception {
        log.debug(">getCACertificate()");
        ISignSessionRemote ss = signhome.create();
        Certificate[] chain = (Certificate[]) ss.getCertificateChain(administrator, caid).toArray(new Certificate[0]);
        X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
        log.debug("<getCACertificate()");

        return rootcert;
    }

    // getCACertificate

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
    }

    // getCACertificate

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
     * @param ks KeyStore
     * @param username username, the owner of the keystore
     * @param kspassword the password used to protect the peystore
     * @param createJKS if a jks should be created
     * @param createPEM if pem files should be created
     *
     * @exception IOException if directory to store keystore cannot be created
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
        }else{
			FileOutputStream os = new FileOutputStream(keyStoreFilename);
			ks.store(os, kspassword.toCharArray());        	
        }

        log.debug("Keystore stored in " + keyStoreFilename);
        log.debug("<storeKeyStore: ks=" + ks.toString() + ", username=" + username);
    }

    // storeKeyStore

    /**
     * Creates files for a user, sends request to CA, receives reploy and creates P12.
     *
     * @param username username
     * @param password user's password
     * @param id of CA used to issue the keystore certificates
     * @param rsaKeys a previously generated RSA keypair
     * @param createJKS if a jks should be created
     * @param createPEM if pem files should be created
     * @param savekeys if generated keys should be saved in db (key recovery)
     *
     * @exception Exception if the certificate is not an X509 certificate
     * @exception Exception if the CA-certificate is corrupt
     * @exception Exception if verification of certificate or CA-cert fails
     * @exception Exception if keyfile (generated by ourselves) is corrupt
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

        // Use username as alias in the keystore
        String alias = username;

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
    }

    // createUser

    /**
     * Does the deed with one user...
     *
     * @param data user data for user
     * @param createJKS if a jks should be created
     * @param createPEM if pem files should be created
     * @param keyrecoverflag if we should try to revoer already existing keys
     *
     * @exception Exception If something goes wrong...
     */
    private void processUser(UserAdminData data, boolean createJKS, boolean createPEM,
        boolean keyrecoverflag) throws Exception {
        KeyPair rsaKeys = null;

        if (usekeyrecovery && keyrecoverflag) {
            // Recover Keys
           IKeyRecoverySessionRemote keyrecoverysession = keyrecoveryhome.create();
           KeyRecoveryData recoveryData = (KeyRecoveryData) keyrecoverysession.keyRecovery(administrator, data.getUsername());
           if (recoveryData != null) {
               rsaKeys = recoveryData.getKeyPair();
           } else {
               throw new Exception("No Key Recovery Data available for user, "+data.getUsername()+" can not be generated.");
           }
         } else {                    
           rsaKeys = KeyTools.genKeys(1024);
         }
         // Get certificate for user and create P12
         if (rsaKeys != null) {
             createUser(data.getUsername(), data.getPassword(), data.getCAId(), rsaKeys, createJKS, createPEM, data.getKeyRecoverable());
         }
     } //processUser

    /**
     * Creates P12-files for all users with status NEW in the local database.
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllNew() throws Exception {
        log.debug(">createAllNew:");
        log.info("Generating for all NEW.");
        createAllWithStatus(UserDataLocal.STATUS_NEW);
        log.debug("<createAllNew:");
    }

    // createAllNew

    /**
     * Creates P12-files for all users with status FAILED in the local database.
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllFailed() throws Exception {
        log.debug(">createAllFailed:");
        log.info("Generating for all FAILED.");
        createAllWithStatus(UserDataLocal.STATUS_FAILED);
        log.debug("<createAllFailed:");
    }

    // createAllFailed

    /**
     * Creates P12-files for all users with status KEYRECOVER in the local database.
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllKeyRecover() throws Exception {
        if (usekeyrecovery) {
            log.debug(">createAllKeyRecover:");
            log.info("Generating for all KEYRECOVER.");
            createAllWithStatus(UserDataLocal.STATUS_KEYRECOVERY);
            log.debug("<createAllKeyRecover:");
        }
    }

    // createAllKeyRecover

    /**
     * Creates P12-files for all users with status in the local database.
     *
     * @param status
     *
     * @exception Exception if something goes wrong...
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
                if (result.size() < IUserAdminSessionRemote.MAXIMUM_QUERY_ROWCOUNT) {
                    stopnow = true;
                }

                Iterator it = result.iterator();
                boolean createJKS;
                boolean createPEM;
                boolean createP12;
                int tokentype = SecConst.TOKEN_SOFT_BROWSERGEN;
                String failedusers = "";
                String successusers = "";

                while (it.hasNext()) {
                    createJKS = false;
                    createPEM = false;
                    createP12 = false;

                    UserAdminData data = (UserAdminData) it.next();

                    if ((data.getPassword() != null) && (data.getPassword().length() > 0)) {
                        try {
                            // get users Token Type.
                            tokentype = data.getTokenType();
                            createP12 = tokentype == SecConst.TOKEN_SOFT_P12;
                            createPEM = tokentype == SecConst.TOKEN_SOFT_PEM;
                            createJKS = tokentype == SecConst.TOKEN_SOFT_JKS;

                            // Only generate supported tokens
                            if (createP12 || createPEM || createJKS) {
                                if (status == UserDataLocal.STATUS_KEYRECOVERY) {
                                    log.info("Retrieving keys for " + data.getUsername());
                                } else {
                                    log.info("Generating keys for " + data.getUsername());
                                }                               

                                // Grab new user, set status to INPROCESS
                                admin.setUserStatus(administrator, data.getUsername(),
                                    UserDataLocal.STATUS_INPROCESS);
                                processUser(data, createJKS, createPEM,
                                    (status == UserDataLocal.STATUS_KEYRECOVERY));

                                // If all was OK , set status to GENERATED
                                admin.setUserStatus(administrator, data.getUsername(),
                                    UserDataLocal.STATUS_GENERATED);

                                // Delete clear text password
                                admin.setClearTextPassword(administrator, data.getUsername(), null);
                                successusers += (":" + data.getUsername());
                                successcount++;
                            } else {
                                log.debug(
                                    "Cannot batchmake browser generated token for user (wrong tokentype)- " +
                                    data.getUsername());
                            }
                        } catch (Exception e) {
                            // If things went wrong set status to FAILED
                            log.error("An error happened, setting status to FAILED.", e);
                            failedusers += (":" + data.getUsername());
                            failcount++;
                            if (status == UserDataLocal.STATUS_KEYRECOVERY) {
                                admin.setUserStatus(administrator, data.getUsername(), UserDataLocal.STATUS_KEYRECOVERY);
                            } else {
                                admin.setUserStatus(administrator, data.getUsername(), UserDataLocal.STATUS_FAILED);
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
    }

    // createAllWithStatus

    /**
     * Creates P12-files for one user in the local database.
     *
     * @param username username
     *
     * @exception Exception if the user does not exist or something goes wrong during generation
     */
    public void createUser(String username) throws Exception {
        log.debug(">createUser(" + username + ")");

        boolean createJKS = false;
        boolean createPEM = false;
        boolean createP12 = false;
        int tokentype = SecConst.TOKEN_SOFT_BROWSERGEN;

        IUserAdminSessionRemote admin = adminhome.create();
        UserAdminData data = admin.findUser(administrator, username);
        int status = data.getStatus();

        if ((data != null) && (data.getPassword() != null) && (data.getPassword().length() > 0)) {
            if ((status == UserDataLocal.STATUS_NEW) ||
                    ((status == UserDataLocal.STATUS_KEYRECOVERY) && usekeyrecovery)) {
                try {
                    // get users Token Type.
                    tokentype = data.getTokenType();
                    createP12 = tokentype == SecConst.TOKEN_SOFT_P12;
                    createPEM = tokentype == SecConst.TOKEN_SOFT_PEM;
                    createJKS = tokentype == SecConst.TOKEN_SOFT_JKS;

                    // Only generate supported tokens
                    if (createP12 || createPEM || createJKS) {
                        if (status == UserDataLocal.STATUS_KEYRECOVERY) {
                            log.info("Retrieving keys for " + data.getUsername());
                        } else {
                            log.info("Generating keys for " + data.getUsername());
                        }

                        // Grab new user, set status to INPROCESS
                        admin.setUserStatus(administrator, data.getUsername(),
                            UserDataLocal.STATUS_INPROCESS);
                        processUser(data, createJKS, createPEM,
                            (status == UserDataLocal.STATUS_KEYRECOVERY));

                        // If all was OK , set status to GENERATED
                        admin.setUserStatus(administrator, data.getUsername(),
                            UserDataLocal.STATUS_GENERATED);

                        // Delete clear text password
                        admin.setClearTextPassword(administrator, data.getUsername(), null);
                        log.info("New user generated successfully - " + data.getUsername());
                    } else {
                        log.info("Cannot batchmake browser generated token for user - " +
                            data.getUsername());
                    }
                } catch (Exception e) {
                    // If things went wrong set status to FAILED
                    log.error("An error happened, setting status to FAILED (if not keyrecovery).");
                    log.error(e);
                    if (status == UserDataLocal.STATUS_KEYRECOVERY) {
                        admin.setUserStatus(administrator, data.getUsername(), UserDataLocal.STATUS_KEYRECOVERY);
                    } else {
                        admin.setUserStatus(administrator, data.getUsername(), UserDataLocal.STATUS_FAILED);
                    }
                    throw new Exception("BatchMakeP12 failed for '" + username + "'.");
                }
            } else {
                log.error("Unknown user, or clear text password is null: " + username);
                throw new Exception("BatchMakeP12 failed for '" + username + "'.");
            }
        }

        log.debug(">createUser(" + username + ")");
    }

    // doit

    /**
     * Main
     *
     * @param args command line arguments
     */
    public static void main(String[] args) {
        try {
            PropertyConfigurator.configure("log4j.properties");

            BatchMakeP12 makep12 = new BatchMakeP12();

            // Create subdirectory 'p12' if it does not exist
            File dir = new File("./p12");
            dir.mkdir();
            makep12.setMainStoreDir("./p12");

            if ((args.length > 0) && args[0].equals("-?")) {
                System.out.println("Usage: batch [username]");
                System.out.println(
                    "Without arguments generates all users with status NEW or FAILED.");
                System.exit(0);
            }

            if (args.length > 0) {
                log.info("Generating Token.");
                makep12.createUser(args[0]);
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
        }
    }

    // main
}


//BatchMakeP12
