
package se.anatom.ejbca.batch;

import java.security.Security;
import java.security.cert.*;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.KeyStoreException;
import java.io.*;
import java.util.Collection;
import java.util.Iterator;

import javax.naming.InitialContext;
import javax.naming.Context;
import javax.naming.NamingException;
import java.rmi.RemoteException;

import org.bouncycastle.jce.provider.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.interfaces.*;

import se.anatom.ejbca.ra.IUserAdminSessionHome;
import se.anatom.ejbca.ra.IUserAdminSession;
import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ra.UserData;
import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSession;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.KeyTools;

import org.apache.log4j.*;

/**
 *
 * This class generates keys and request certificates for all users with status NEW. The result is generated PKCS12-files.
 *
 * @version $Id: BatchMakeP12.java,v 1.8 2002-01-25 13:13:39 anatom Exp $
 *
 */

public class BatchMakeP12 {

    /** For logging */
    private static Category cat = Category.getInstance(BatchMakeP12.class.getName());

    /** Where created P12-files are stored, default /<username>.p12 */
    private String mainStoreDir = "";

    private IUserAdminSessionHome adminhome;
    private ISignSessionHome signhome;

    static public Context getInitialContext() throws NamingException{
        //System.out.println(">GetInitialContext");
        // jndi.properties must exist in classpath
        Context ctx = new javax.naming.InitialContext();
        //System.out.println("<GetInitialContext");
        return ctx;
    }
    /**
     * Creates new BatchMakeP12 object.
     *
     * @exception javax.naming.NamingException
     * @exception CreateException
     * @exception RemoteException
     */
    public BatchMakeP12() throws javax.naming.NamingException, javax.ejb.CreateException, java.rmi.RemoteException, java.io.IOException {
        cat.debug(">BatchMakeP12:");

        // Bouncy Castle security provider
        Security.addProvider(new BouncyCastleProvider());

        Context jndiContext = getInitialContext();
        Object obj = jndiContext.lookup("UserAdminSession");
        adminhome = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj, IUserAdminSessionHome.class);
        Object obj1 = jndiContext.lookup("RSASignSession");
        signhome = (ISignSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ISignSessionHome.class);

        cat.debug("<BatchMakeP12:");
    } // BatchMakeP12

    /**
     * Gets CA-certificate(s).
     *
     * @return X509Certificate
     */
    private X509Certificate getCACertificate()
    throws Exception {
        cat.debug(">getCACertificate()");
        ISignSession ss = signhome.create();
        Certificate[] chain = ss.getCertificateChain();
        X509Certificate rootcert = (X509Certificate)chain[chain.length-1];
        cat.debug("<getCACertificate()");
        return rootcert;

    } // getCACertificate

    /** Sets the location where generated P12-files will be stored, full name will be: mainStoreDir/<username>.p12.
     * @param dir existing directory
     */
    public void setMainStoreDir(String dir) {
        mainStoreDir = dir;
    }
    /**
     * Stores keystore.
     *
     * @param ks KeyStore
     * @param user username, the owner of the keystore
     * @param passwprd. the password used to protect the peystore
     * @exception IOException if directory to store keystore cannot be created
     */
    private void storeKeyStore(KeyStore ks, String username, String kspassword) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        cat.debug(">storeKeyStore: ks=" + ks.toString() + ", username=" + username);
        // Where to store it?
        if (mainStoreDir == null)
            throw new IOException("Can't find directory to store keystore in.");
        String keyStoreFilename = mainStoreDir + "/" + username+ ".p12";

        FileOutputStream os = new FileOutputStream(keyStoreFilename);
        ks.store(os, kspassword.toCharArray());

        cat.debug("Keystore stored in " + keyStoreFilename);
        cat.debug("<storeKeyStore: ks=" + ks.toString() + ", username=" + username);
    } // storeKeyStore

    /**
     * Creates files for a user, sends request to CA, receives reploy and creates P12.
     *
     * @param username username
     * @param password user's password
     * @param rsaKeys a previously generated RSA keypair
     * @exception Exception if the certificate is not an X509 certificate
     * @exception Exception if the CA-certificate is corrupt
     * @exception Exception if verification of certificate or CA-cert fails
     * @exception Exception if keyfile (generated by ourselves) is corrupt
     */
    private void createUser(String username, String password, KeyPair rsaKeys)
    throws Exception {


        cat.debug(">createUser: username=" + username + ", hiddenpwd, keys=" + rsaKeys.toString());

        // Send the certificate request to the CA
        ISignSession ss = signhome.create();
        X509Certificate cert = (X509Certificate)ss.createCertificate(username, password, rsaKeys.getPublic());

        // Make a certificate chain from the certificate and the CA-certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate[] chain = new X509Certificate[2];
        chain[0] = cert;
        // CA-certificate
        chain[1] = getCACertificate();
        if (CertTools.isSelfSigned(chain[1])) {
            try {
                chain[1].verify(chain[1].getPublicKey());
            } catch (GeneralSecurityException se) {
                throw new Exception("RootCA certificate does not verify");
            }
        }
        else
            throw new Exception("RootCA certificate not self-signed");

        // Verify that the user-certificate is signed by our CA
        try {
            chain[0].verify(chain[1].getPublicKey());
        } catch (GeneralSecurityException se) {
            throw new Exception("Generated certificate does not verify using CA-certificate.");
        }


        // Use CommonName as alias in the keystore
        String alias = CertTools.getPartFromDN(cert.getSubjectDN().toString(), "CN");
        // Store keys and certificates in keystore.
        KeyStore p12 = KeyTools.createP12(alias, rsaKeys.getPrivate(), chain[0], chain[1]);
        storeKeyStore(p12, username, password);
        cat.info("Created P12 for " + username+ ".");
        cat.debug(">createUser: username=" + username + ", hiddenpwd, keys=" + rsaKeys.toString());
    } // doit

    /**
     * Does the deed with one user...
     *
     * @exception Exception If something goes wrong...
     */
     private void processUser(UserAdminData data) throws Exception {
         // Generate keys
         KeyPair rsaKeys = KeyTools.genKeys(1024);
         // Get certificate for user and create P12
         createUser(data.getUsername(), data.getPassword(), rsaKeys);
     } //processUser

    /**
     * Creates P12-files for all users with status NEW in the local database.
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllNew() throws Exception {
        cat.debug(">createAllNew:");
        createAllWithStatus(UserData.STATUS_NEW);
        cat.debug("<createAllNew:");
    } // createAllNew
    /**
     * Creates P12-files for all users with status FAILED in the local database.
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllFailed() throws Exception {
        cat.debug(">createAllFailed:");
        createAllWithStatus(UserData.STATUS_FAILED);
        cat.debug("<createAllFailed:");
    } // createAllFailed
    
    /**
     * Creates P12-files for all users with status in the local database.
     *
     * @param status
     *
     * @exception Exception if something goes wrong...
     */
    public void createAllWithStatus(int status) throws Exception {
        cat.debug(">createAllWithStatus: "+status);

        IUserAdminSession admin = adminhome.create();

        Collection result = admin.findAllUsersByStatus(status);
        Iterator it = result.iterator();
        String failedusers = "";
        int failcount = 0;
        String successusers = "";
        int successcount = 0;
        while( it.hasNext() ) {
            UserAdminData data = (UserAdminData) it.next();
            if (data.getPassword() != null) {                
                try {
                    cat.debug("Generating keys for " + data.getUsername());
                    // Grab new user, set status to INPROCESS
                    admin.setUserStatus(data.getUsername(), UserData.STATUS_INPROCESS);
                    processUser(data);
                    // If all was OK , set status to GENERATED
                    admin.setUserStatus(data.getUsername(), UserData.STATUS_GENERATED);
                    // Delete clear text password
                    admin.setClearTextPassword(data.getUsername(), null);
                    successusers += ":" + data.getUsername();
                    successcount++;
                } catch (Exception e) {
                    // If things went wrong set status to FAILED
                    cat.error("An error happened, setting status to FAILED.");
                    cat.error(e);
                    failedusers += ":" + data.getUsername();
                    failcount++;
                    admin.setUserStatus(data.getUsername(), UserData.STATUS_FAILED);
                }
            } else
                cat.debug("User '"+data.getUsername()+"' does not have clear text password.");
        }
        if (failedusers != "")
            throw new Exception("BatchMakeP12 failed for " + failcount + " users (" + successcount + " succeeded) - " + failedusers);
        cat.debug(successcount + " new users generated successfully - " + successusers);
        cat.debug("<createAllWithStatus: "+status);

    } // createAllWithStatus

    /**
     * Creates P12-files for one user in the local database.
     *
     * @params username username
     * @exception Exception if the user does not exist or something goes wrong during generation
     */
    public void createUser(String username) throws Exception {
        cat.debug(">createUser("+username+")");

        IUserAdminSession admin = adminhome.create();
        UserAdminData data = admin.findUser(username);
        if (data != null) {
            try {
                cat.debug("Creating P12 for " + data.getUsername());
                // Grab new user, set status to INPROCESS
                admin.setUserStatus(data.getUsername(), UserData.STATUS_INPROCESS);
                processUser(data);
                // If all was OK , set status to GENERATED
                admin.setUserStatus(data.getUsername(), UserData.STATUS_GENERATED);
                // Delete clear text password
                admin.setClearTextPassword(data.getUsername(), null);
            } catch (Exception e) {
                // If things went wrong set status to FAILED
                cat.error("An error happened, setting status to FAILED.");
                cat.error(e);
                admin.setUserStatus(data.getUsername(), UserData.STATUS_FAILED);
                throw new Exception("BatchMakeP12 failed for - " + data.getUsername());
            }
        }
        else {
            cat.error("Unknown user: " + username);
            throw new Exception("BatchMakeP12 failed for - " + data.getUsername());
        }
        cat.debug("New user generated successfully - " + data.getUsername());
        cat.debug(">createUser("+username+")");

    } // doit

    public static void main(String[] args) {
        try {

            BasicConfigurator.configure();
            BatchMakeP12 makep12 = new BatchMakeP12();
            if (args.length > 0) {
                // Make P12 for specified user
                makep12.createUser(args[0]);
            } else {
                // Create subdirectory 'p12' if it does not exist
                File dir = new File("./p12");
                dir.mkdir();
                makep12.setMainStoreDir("./p12");
                // Make P12 for all NEW users in local DB
                makep12.createAllNew();
                // Make P12 for all FAILED users in local DB
                makep12.createAllFailed();
            }

        } catch( Exception e ) {
            e.printStackTrace();
        }

    } // main

} //BatchMakeP12

