
package se.anatom.ejbca.admin;

import java.io.*;
import javax.naming.*;
import java.security.Security;
import java.security.KeyPair;
import java.security.Provider;
import java.security.cert.Certificate;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.InvalidKeyException;
import java.security.SignatureException;
import javax.ejb.CreateException;
import java.rmi.RemoteException;

import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.*;

import se.anatom.ejbca.ca.sign.ISignSessionHome;
import se.anatom.ejbca.ca.sign.ISignSessionRemote;
import se.anatom.ejbca.IJobRunnerSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.util.CertTools;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.log.Admin;

/** Base for CA commands, contains comom functions for CA operations
 *
 * @version $Id: BaseCaAdminCommand.java,v 1.8 2003-01-12 17:16:30 anatom Exp $
 */
public abstract class BaseCaAdminCommand extends BaseAdminCommand {

    /** Private key alias in PKCS12 keystores */
    protected String privKeyAlias = "privateKey";
    protected char[] privateKeyPass = null;
    
    protected Admin administrator = null;

    /** Creates a new instance of BaseCaAdminCommand */
    public BaseCaAdminCommand(String[] args) {
        super(args);

        // Install BouncyCastle provider
        Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        int result = Security.addProvider(BCJce);
        
        administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    }

    /** Retrieves the complete certificate chain from the CA
     *
     *@return array of certificates, from ISignSession.getCertificateChain()
     */
    protected Certificate[] getCertChain() {
        debug(">getCertChain()");
        try {
            Context ctx = getInitialContext();
            ISignSessionHome home = (ISignSessionHome)javax.rmi.PortableRemoteObject.narrow(ctx.lookup("RSASignSession"), ISignSessionHome.class );
            ISignSessionRemote ss = home.create();
            Certificate[] chain = ss.getCertificateChain(administrator);
            return chain;
        } catch (Exception e) {
            error("Error while getting certfificate chain from CA.", e);
        }
        debug("<getCertChain()");
        return null;
    } // getCertChain

    protected void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile) throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, SignatureException {
        debug(">makeCertRequest: dn='"+dn+"', reqfile='"+reqfile+"'.");
        PKCS10CertificationRequest req = new PKCS10CertificationRequest(
        "SHA1WithRSA", CertTools.stringToBcX509Name(dn), rsaKeys.getPublic(), null, rsaKeys.getPrivate());
        /* We don't use these uneccesary attributes
        DERConstructedSequence kName = new DERConstructedSequence();
        DERConstructedSet  kSeq = new DERConstructedSet();
        kName.addObject(PKCSObjectIdentifiers.pkcs_9_at_emailAddress);
        kSeq.addObject(new DERIA5String("foo@bar.se"));
        kName.addObject(kSeq);
        req.setAttributes(kName);
         */
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);
        dOut.writeObject(req);
        dOut.close();
        ByteArrayInputStream bIn = new ByteArrayInputStream(bOut.toByteArray());
        DERInputStream dIn = new DERInputStream(bIn);
        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest((DERConstructedSequence)dIn.readObject());
        boolean verify = req2.verify();
        System.out.println("Verify returned " + verify);
        if (verify == false) {
            System.out.println("Aborting!");
            return;
        }
        FileOutputStream os1 = new FileOutputStream(reqfile);
        os1.write("-----BEGIN CERTIFICATE REQUEST-----\n".getBytes());
        os1.write(Base64.encode(bOut.toByteArray()));
        os1.write("\n-----END CERTIFICATE REQUEST-----\n".getBytes());
        os1.close();
        System.out.println("CertificationRequest '"+reqfile+"' generated succefully.");
        debug("<makeCertRequest: dn='"+dn+"', reqfile='"+reqfile+"'.");
    } // makeCertRequest

    protected void createCRL() throws NamingException, CreateException, RemoteException {
        debug(">createCRL()");
      try{  
        Context context = getInitialContext();
        IJobRunnerSessionHome home  = (IJobRunnerSessionHome)javax.rmi.PortableRemoteObject.narrow( context.lookup("CreateCRLSession") , IJobRunnerSessionHome.class );
        home.create().run(administrator);
        ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CertificateStoreSession"), ICertificateStoreSessionHome.class);
        ICertificateStoreSessionRemote storeremote = storehome.create();
        int number = storeremote.getLastCRLNumber(administrator);
        System.out.println("CRL with number " + number+ " generated.");
      } catch (Exception e) {
          error("Error while getting certfificate chain from CA.", e);
      }        
        debug(">createCRL()");
   } // createCRL

}
