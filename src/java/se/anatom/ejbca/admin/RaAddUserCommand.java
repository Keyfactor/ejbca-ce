
package se.anatom.ejbca.admin;

import java.io.*;
import javax.naming.*;
import javax.ejb.FinderException;

import se.anatom.ejbca.ra.UserAdminData;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.Profile;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillProfile;

/** Adds a user to the database.
 *
 * @version $Id: RaAddUserCommand.java,v 1.5 2002-08-27 12:41:06 herrvendil Exp $
 */
public class RaAddUserCommand extends BaseRaAdminCommand {

    /** Creates a new instance of RaAddUserCommand */
    public RaAddUserCommand(String[] args) {
        super(args);
    }

    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            InitialContext jndicontext = new InitialContext();
            
            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();     
            
            String[] certtypenames = (String[]) certificatesession.getCertificateTypeNames().toArray((Object[]) new String[0]);
            if (args.length < 6) {
                System.out.println("Usage: RA adduser <username> <password> <dn> <email> <type> [<certificatetype>]  [<profile>] ");
                System.out.println("Type (mask): INVALID=0; END-USER=1; CA=2; RA=4; ROOTCA=8; CAADMIN=16; RAADMIN=32");
                
                System.out.print("Existing certificatetypes  : ");
                for(int i=0; i < certtypenames.length-1; i++){
                  System.out.print(certtypenames[i] + ", ");
                }
                System.out.print(certtypenames[certtypenames.length-1] + "\n");
                
                System.out.println("If the user does not have an email address, use the value 'null'. ");
                return;
            }
            String username = args[1];
            String password = args[2];
            String dn = args[3];
            String email = args[4];
            int type = Integer.parseInt(args[5]);
            int profileid =  UserAdminData.NO_PROFILE;
            int certificatetypeid = UserAdminData.NO_CERTIFICATETYPE;
            boolean error = false;
            

            if(args.length == 6){
              // Use certificate type, no profile.              
              certificatetypeid = ICertificateStoreSessionRemote.FIXED_ENDUSER;
              profileid = IRaAdminSessionRemote.EMPTY_PROFILEID;
            }            
            
            if(args.length == 7){
              // Use certificate type, no profile.              
              certificatetypeid = certificatesession.getCertificateTypeId(args[6]);
              profileid = IRaAdminSessionRemote.EMPTY_PROFILEID;
            }
            
            if(args.length == 8){
              // Use certificate type and profile.
              obj1 = jndicontext.lookup("RaAdminSession");
              IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"), 
                                                                                 IRaAdminSessionHome.class);
              IRaAdminSessionRemote raadminsession = raadminsessionhome.create();      
              profileid = raadminsession.getProfileId(args[7]);
              certificatetypeid = certificatesession.getCertificateTypeId(args[6]);
            }            
 
            if(certificatetypeid == UserAdminData.NO_CERTIFICATETYPE){ // Certificate type not found i database.
              System.out.println("Error : Couldn't find certificate type in database");
              error = true;
            }    
             if(profileid == UserAdminData.NO_PROFILE){ // Certificate type not found i database.
              System.out.println("Error : Couldn't find profile in database" );
              error = true;
            }               
            
            // Check if username already exists.
            try{
              if(getAdminSession().findUser(username) != null){;
                System.out.println("Error : User already exists in the database." );                
                error= true;                
              }
            }catch(FinderException e){
 
            }
            
            if(!error){
              System.out.println("Trying to add user:");
              System.out.println("Username: "+username);
              System.out.println("Password (hashed only): "+password);
              System.out.println("DN: "+dn);
              System.out.println("Email: "+email);
              System.out.println("Type: "+type);
              if (email.equals("null"))
                  email = null;
              try{
                getAdminSession().addUser(username, password, dn, email, type,false, profileid, certificatetypeid); 
                System.out.println("User '"+username+"' has been added.");
                System.out.println();
                System.out.println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");              
              }catch(AuthorizationDeniedException e){
                  System.out.println("Error : Not authorized to add user to given profile."); 
              }catch(UserDoesntFullfillProfile e){
                 System.out.println("Error : Given userdata doesn't fullfill profile.");                
              }    
            }    
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute
}
