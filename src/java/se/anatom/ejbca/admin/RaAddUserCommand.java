
package se.anatom.ejbca.admin;

import javax.naming.*;
import javax.ejb.FinderException;

import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import se.anatom.ejbca.SecConst;

/** Adds a user to the database.
 *
 * @version $Id: RaAddUserCommand.java,v 1.14 2003-01-12 17:16:31 anatom Exp $
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

            obj1 = jndicontext.lookup("RaAdminSession");
            IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                                                                 IRaAdminSessionHome.class);
            IRaAdminSessionRemote raadminsession = raadminsessionhome.create();

            String[] certprofnames = (String[]) certificatesession.getCertificateProfileNames(administrator).toArray((Object[]) new String[0]);
            String[] endentityprofilenames = (String[]) raadminsession.getEndEntityProfileNames(administrator).toArray((Object[]) new String[0]);

            if (args.length < 8) {
                System.out.println("Usage: RA adduser <username> <password> <dn> <subjectAltName> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] ");
                System.out.println();
                System.out.println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
                System.out.println("SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>\"");
                System.out.println("Type (mask): INVALID=0; END-USER=1; CA=2;  ROOTCA=8; ADMINISTRATOR=64");
                System.out.println("Token      : User Generated=" + SecConst.TOKEN_SOFT_BROWSERGEN + "; P12=" + SecConst.TOKEN_SOFT_P12 + "; JKS="
                                    + SecConst.TOKEN_SOFT_JKS + ";  PEM=" + SecConst.TOKEN_SOFT_PEM);

                System.out.print("Existing certificate profiles  : ");

                for(int i=0; i < certprofnames.length-1; i++){
                  System.out.print(certprofnames[i] + ", ");
                }
                System.out.print(certprofnames[certprofnames.length-1] + "\n");


                System.out.print("Existing endentity profiles  : ");
                for(int i=0; i < endentityprofilenames.length-1; i++){
                  System.out.print(endentityprofilenames[i] + ", ");
                }
                System.out.print(endentityprofilenames[endentityprofilenames.length-1] + "\n");

                System.out.println("If the user does not have an email address, use the value 'null'. ");
                return;
            }


            String username = args[1];
            String password = args[2];
            String dn = args[3];
            String subjectaltname = args[4];
            String email = args[5];
            int type  = Integer.parseInt(args[6]);
            int token = Integer.parseInt(args[7]);
            int profileid =  SecConst.EMPTY_ENDENTITYPROFILE;
            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            boolean error = false;

            if(args.length == 9){
              // Use certificate type, no profile.
              certificatetypeid = certificatesession.getCertificateProfileId(administrator, args[8]);
              profileid = SecConst.EMPTY_ENDENTITYPROFILE;
            }

            if(args.length == 10){
              // Use certificate type and profile.
              profileid = raadminsession.getEndEntityProfileId(administrator, args[9]);
              certificatetypeid = certificatesession.getCertificateProfileId(administrator, args[8]);
            }

            if(!validToken(token)){
              System.out.println("Error : Invalid token number.");
              error = true;
            }

            if(certificatetypeid == SecConst.PROFILE_NO_CERTIFICATEPROFILE){ // Certificate profile not found i database.
              System.out.println("Error : Couldn't find certificate profile in database.");
              error = true;
            }
             if(profileid == 0){ // End entity profile not found i database.
              System.out.println("Error : Couldn't find end entity profile in database." );
              error = true;
            }

            // Check if username already exists.
            try{
              if(getAdminSession().findUser(administrator, username) != null){;
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
              System.out.println("Token: "+token);
              if (email.equals("null"))
                  email = null;
              try{
                getAdminSession().addUser(administrator, username, password, dn, subjectaltname, email, false, profileid, certificatetypeid,
                                         (type & SecConst.USER_ADMINISTRATOR) == SecConst.USER_ADMINISTRATOR,
                                         (type & SecConst.USER_KEYRECOVERABLE) == SecConst.USER_KEYRECOVERABLE,
                                          token,0);
                System.out.println("User '"+username+"' has been added.");
                System.out.println();
                System.out.println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");
              }catch(AuthorizationDeniedException e){
                  System.out.println("Error : Not authorized to add user to given profile.");
              }catch(UserDoesntFullfillEndEntityProfile e){
                 System.out.println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
              }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    } // execute

    private boolean validToken(int token){
       return (token == SecConst.TOKEN_SOFT_BROWSERGEN || token == SecConst.TOKEN_SOFT_P12  || token == SecConst.TOKEN_SOFT_PEM || token == SecConst.TOKEN_SOFT_JKS );
    }
}
