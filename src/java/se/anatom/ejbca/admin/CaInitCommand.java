package se.anatom.ejbca.admin;

import java.util.Collection;
import java.util.ArrayList;
import java.util.Vector;

import javax.naming.Context;

import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.CAInfo;
import se.anatom.ejbca.ca.caadmin.X509CAInfo;
import se.anatom.ejbca.ca.caadmin.CATokenInfo;
import se.anatom.ejbca.ca.caadmin.SoftCATokenInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.ExtendedCAServiceInfo;
import se.anatom.ejbca.ca.caadmin.extendedcaservices.OCSPCAServiceInfo;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.SecConst;

import se.anatom.ejbca.util.CertTools;


/**
 * Inits the CA by creating the first CRL and publiching the CRL and CA certificate.
 *
 * @version $Id: CaInitCommand.java,v 1.23 2004-01-07 19:50:19 anatom Exp $
 */
public class CaInitCommand extends BaseCaAdminCommand {
    /** Pointer to main certificate store */
    private static ICertificateStoreSessionRemote certificateStore = null;

    /** A vector of publishers where certs and CRLs are stored */
    private static Vector publishers = null;

    /**
     * Creates a new instance of CaInitCommand
     *
     * @param args command line arguments
     */
    public CaInitCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        // Create new CA.
        if (args.length < 6) {
           String msg = "Used to create a Root CA.";
           msg += "\nUsage: CA init <caname> <dn> <keysize> <validity-days> <policyID>";
           msg += "\npolicyId can be 'null' if no Certificate Policy extension should be present, or\nobjectID as '2.5.29.32.0'.";
           throw new IllegalAdminCommandException(msg);
        }
            
        try {        
            String caname = args[1];
            String dn = CertTools.stringToBCDNString(args[2]);
            int keysize = Integer.parseInt(args[3]);
            int validity = Integer.parseInt(args[4]);
            String policyId = args[5];
            if (policyId.equals("null"))
              policyId = null;
              
            System.out.println("Initializing CA");            
            Context context = getInitialContext();
            ICAAdminSessionHome caadminsessionhome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("CAAdminSession"), ICAAdminSessionHome.class);
            ICAAdminSessionRemote caadminsession = caadminsessionhome.create();
            
            if(caadminsession.getAllCACertificates(administrator).size() > 0){
               System.out.println("Error: A CA already exists in database");   
            }else{
                
              System.out.println("Generating rootCA keystore:");
              System.out.println("DN: "+dn);
              System.out.println("Keysize: "+keysize);
              System.out.println("Validity (days): "+validity);
              System.out.println("Policy ID: "+policyId);
                            
              initAuthorizationModule(dn.hashCode());

                       
              SoftCATokenInfo catokeninfo = new SoftCATokenInfo();
              catokeninfo.setKeySize(keysize);
              catokeninfo.setAlgorithm(SoftCATokenInfo.KEYALGORITHM_RSA);
              catokeninfo.setSignatureAlgorithm(CATokenInfo.SIGALG_SHA_WITH_RSA);
			  // Create and active OSCP CA Service.
			  ArrayList extendedcaservices = new ArrayList();
			  extendedcaservices.add(
				new OCSPCAServiceInfo(ExtendedCAServiceInfo.STATUS_ACTIVE,
									  "CN=OCSPSignerCertificate, " + dn,
									  "",
									  2048,
									  OCSPCAServiceInfo.KEYALGORITHM_RSA));
              
            
              X509CAInfo cainfo = new X509CAInfo(dn, 
                                               caname, SecConst.CA_ACTIVE,
                                               "", SecConst.CERTPROFILE_FIXED_ROOTCA,
                                               validity, 
                                               null, // Expiretime                                             
                                               CAInfo.CATYPE_X509,
                                               CAInfo.SELFSIGNED,
                                               (Collection) null,
                                               catokeninfo,
                                               "Initial CA",
                                               -1, null,
                                               policyId, // PolicyId
                                               24, // CRLPeriod
                                               (Collection) new ArrayList(),
                                               true, // Authority Key Identifier
                                               false, // Authority Key Identifier Critical
                                               true, // CRL Number
                                               false, // CRL Number Critical
                                               true, // Finish User
				                               extendedcaservices);         
            
              System.out.println("Creating CA...");
              caadminsession.createCA(administrator, cainfo);
            
              int caid = caadminsession.getCAInfo(administrator, caname).getCAId();
			  System.out.println("CAId for created CA: " + caid);
              
              // Second create (and publish) CRL
              createCRL(dn);
              System.out.println("-Created and published initial CRL.");
              System.out.println("CA initialized");
            }  
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
    private void initAuthorizationModule(int caid) throws Exception{
      System.out.println("Initalizing Temporary Authorization Module.");  
      Context context = getInitialContext();
      IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(context.lookup("AuthorizationSession"), IAuthorizationSessionHome.class);   
      IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();  
      authorizationsession.initialize(administrator, caid);
    } // initAuthorizationModule
}
