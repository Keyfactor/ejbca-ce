
package se.anatom.ejbca.admin;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import javax.naming.*;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.UserDataRemote;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionRemote;
import se.anatom.ejbca.keyrecovery.IKeyRecoverySessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.util.CertTools;


/** Find details of a user in the database.
 *
 * @version $Id: RaFindUserCommand.java,v 1.4 2003/01/12 17:16:31 anatom Exp $
 */
public class RaKeyRecoverCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaFindUserCommand */
    public RaKeyRecoverCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            if (args.length != 3) {
                System.out.println("Usage: RA keyrecover <CertificateSN (HEX)> <IssuerDN>");
                return;
            }
            InitialContext jndicontext = new InitialContext();            
            
            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

            obj1 = jndicontext.lookup("KeyRecoverySession");
            IKeyRecoverySessionHome keyrecoverysessionhome = (IKeyRecoverySessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("KeyRecoverySession"),
                                                                                 IKeyRecoverySessionHome.class);
            IKeyRecoverySessionRemote keyrecoverysession = keyrecoverysessionhome.create();
            
            BigInteger certificatesn = new BigInteger(args[1],16);
            String issuerdn = args[2];

             boolean usekeyrecovery = getAdminSession().loadGlobalConfiguration(administrator).getEnableKeyRecovery();  
             if(!usekeyrecovery){
               System.out.println("Keyrecovery have to be enabled in the system configuration in order to use this command.");
               return;                   
             }   
              
             X509Certificate cert = (X509Certificate) certificatesession.findCertificateByIssuerAndSerno(
                                                                             administrator, CertTools.stringToBCDNString(issuerdn), 
                                                                             certificatesn);
              
             if(cert == null){
               System.out.println("Certificate couldn't be found in database.");
               return;              
             }
              
             String username = certificatesession.findUsernameByCertSerno(administrator, certificatesn);
              
             if(!keyrecoverysession.existsKeys(administrator,cert)){
               System.out.println("Specified keys doesn't exist in database.");
               return;                  
             }
              
             if(keyrecoverysession.isUserMarked(administrator,username)){
               System.out.println("User is already marked for recovery.");
               return;                     
             }
  
             keyrecoverysession.markAsRecoverable(administrator, 
                                                  cert);
        
             getAdminSession().setUserStatus(administrator, username, UserDataRemote.STATUS_KEYRECOVERY); 
 
             System.out.println("Keys corresponding to given certificate has been marked for recovery.");                           
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
    
}
