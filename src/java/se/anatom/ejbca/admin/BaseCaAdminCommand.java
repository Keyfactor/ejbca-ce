package se.anatom.ejbca.admin;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.rmi.RemoteException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collection;

import javax.ejb.CreateException;
import javax.naming.Context;
import javax.naming.NamingException;

import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.jce.PKCS10CertificationRequest;

import se.anatom.ejbca.IJobRunnerSessionHome;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.util.Base64;
import se.anatom.ejbca.util.CertTools;


/**
 * Base for CA commands, contains comom functions for CA operations
 *
 * @version $Id: BaseCaAdminCommand.java,v 1.16 2003-11-20 15:23:21 anatom Exp $
 */
public abstract class BaseCaAdminCommand extends BaseAdminCommand {
    /** Private key alias in PKCS12 keystores */
    protected String privKeyAlias = "privateKey";
    protected char[] privateKeyPass = null;
    protected Admin administrator = null;

    protected ICAAdminSessionRemote caadminsession = null;
    
    /**
     * Creates a new instance of BaseCaAdminCommand
     *
     * @param args command line arguments
     */
    public BaseCaAdminCommand(String[] args) {
        super(args);
        // Install BouncyCastle provider
        CertTools.installBCProvider();
        administrator = new Admin(Admin.TYPE_CACOMMANDLINE_USER);
    }
    
    /** Retrieves the complete certificate chain from the CA
     *
     * @param human readable name of CA 
     * @return array of certificates, from ISignSession.getCertificateChain()
     */   
    protected Collection getCertChain(String caname) throws Exception{
        debug(">getCertChain()");
        Collection returnval = new ArrayList();
        try {
            CAInfo cainfo = this.getCAAdminSessionRemote().getCAInfo(administrator,caname);
            if (cainfo != null) {
                returnval = cainfo.getCertificateChain();
            } 
        } catch (Exception e) {
            error("Error while getting certfificate chain from CA.", e);
        }
        debug("<getCertChain()");
        return returnval;
    } // getCertChain 

    protected void makeCertRequest(String dn, KeyPair rsaKeys, String reqfile)
        throws NoSuchAlgorithmException, IOException, NoSuchProviderException, InvalidKeyException, 
            SignatureException {
        debug(">makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");

        PKCS10CertificationRequest req = new PKCS10CertificationRequest("SHA1WithRSA",
                CertTools.stringToBcX509Name(dn), rsaKeys.getPublic(), null, rsaKeys.getPrivate());

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

        PKCS10CertificationRequest req2 = new PKCS10CertificationRequest(bOut.toByteArray());
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
        System.out.println("CertificationRequest '" + reqfile + "' generated successfully.");
        debug("<makeCertRequest: dn='" + dn + "', reqfile='" + reqfile + "'.");
    } // makeCertRequest

    protected void createCRL(String issuerdn) throws NamingException, CreateException, RemoteException {
        debug(">createCRL()");

        try {
            Context context = getInitialContext();
            IJobRunnerSessionHome home = (IJobRunnerSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
                        "CreateCRLSession"), IJobRunnerSessionHome.class);
            home.create().run(administrator, issuerdn);

            ICertificateStoreSessionHome storehome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
                        "CertificateStoreSession"), ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote storeremote = storehome.create();
            int number = storeremote.getLastCRLNumber(administrator, issuerdn);
            System.out.println("CRL with number " + number + " generated.");
        } catch (Exception e) {
            error("Error while getting certfificate chain from CA.", e);
        }

        debug(">createCRL()");
   } // createCRL
    
   protected String getIssuerDN(String caname) throws Exception{            
      CAInfo cainfo = getCAAdminSessionRemote().getCAInfo(administrator, caname);
      return cainfo.getSubjectDN();  
   }
   
   protected ICAAdminSessionRemote getCAAdminSessionRemote() throws Exception{
      if(caadminsession == null){
        Context ctx = getInitialContext();
        ICAAdminSessionHome home = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(ctx.lookup("CAAdminSession"), ICAAdminSessionHome.class );            
        caadminsession = home.create();          
      } 
      return caadminsession;
   } // createCRL
}
