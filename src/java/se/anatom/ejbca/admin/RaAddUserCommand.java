package se.anatom.ejbca.admin;

import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;

import javax.ejb.FinderException;
import javax.naming.InitialContext;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.authorization.AuthorizationDeniedException;
import se.anatom.ejbca.authorization.IAuthorizationSessionHome;
import se.anatom.ejbca.authorization.IAuthorizationSessionRemote;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionHome;
import se.anatom.ejbca.ca.caadmin.ICAAdminSessionRemote;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.hardtoken.AvailableHardToken;
import se.anatom.ejbca.hardtoken.IHardTokenSessionHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionRemote;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;




/**
 * Adds a user to the database.
 *
 * @version $Id: RaAddUserCommand.java,v 1.28 2003-10-29 14:25:54 herrvendil Exp $
 */
public class RaAddUserCommand extends BaseRaAdminCommand {
    /**
     * Creates a new instance of RaAddUserCommand
     *
     * @param args command line arguments
     */
    public RaAddUserCommand(String[] args) {
        super(args);
    }

    /**
     * Runs the command
     *
     * @throws IllegalAdminCommandException Error in command args
     * @throws ErrorAdminCommandException Error running command
     */
    public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException {
        try {
            InitialContext jndicontext = new InitialContext();

            Object obj1 = jndicontext.lookup("CertificateStoreSession");
            ICertificateStoreSessionHome certificatesessionhome = (ICertificateStoreSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1,
                    ICertificateStoreSessionHome.class);
            ICertificateStoreSessionRemote certificatesession = certificatesessionhome.create();

            IRaAdminSessionHome raadminsessionhome = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("RaAdminSession"),
                                                                                 IRaAdminSessionHome.class);

            IRaAdminSessionRemote raadminsession = raadminsessionhome.create();


            ICAAdminSessionHome caadminsessionhome = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("CAAdminSession"),
                                                                                 ICAAdminSessionHome.class);
            ICAAdminSessionRemote caadminsession = caadminsessionhome.create();                       

            IAuthorizationSessionHome authorizationsessionhome = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("AuthorizationSession"),
                                                                                 IAuthorizationSessionHome.class);
            IAuthorizationSessionRemote authorizationsession = authorizationsessionhome.create();                       
            
            
            GlobalConfiguration globalconfiguration = raadminsession.loadGlobalConfiguration(administrator);
            boolean usehardtokens = globalconfiguration.getIssueHardwareTokens();
            boolean usekeyrecovery = globalconfiguration.getEnableKeyRecovery();
            String[] hardtokenissueraliases = null;
            AvailableHardToken[] availabletokens = new AvailableHardToken[0];

            IHardTokenSessionRemote hardtokensession=null;
            if(usehardtokens){  
              IHardTokenSessionHome hardtokensessionhome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("HardTokenSession"),
                                                                                 IHardTokenSessionHome.class);
              hardtokensession = hardtokensessionhome.create();
              hardtokenissueraliases = (String[]) hardtokensession.getHardTokenIssuerAliases(administrator).toArray((Object[]) new String[0]);
              availabletokens = hardtokensession.getAvailableHardTokens();
            }  
            
            if (args.length < 9) {
                Collection certprofileids = certificatesession.getAuthorizedCertificateProfileIds(administrator, SecConst.CERTTYPE_ENDENTITY);
                HashMap certificateprofileidtonamemap = certificatesession.getCertificateProfileIdToNameMap(administrator);
                
                Collection endentityprofileids =  raadminsession.getAuthorizedEndEntityProfileIds(administrator);
                HashMap endentityprofileidtonamemap = raadminsession.getEndEntityProfileIdToNameMap(administrator);
                
                Collection caids = authorizationsession.getAuthorizedCAIds(administrator);
                HashMap caidtonamemap = caadminsession.getCAIdToNameMap(administrator);
                
                if( usehardtokens)
                  System.out.println("Usage: RA adduser <username> <password> <dn> <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] [<hardtokenissuer>]");
                else
                  System.out.println("Usage: RA adduser <username> <password> <dn> <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] ");


                System.out.println("");
                System.out.println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
                System.out.println(
                    "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>\"");

                if (usekeyrecovery) {
                    System.out.println(
                        "Type (mask): INVALID=0; END-USER=1; ADMINISTRATOR=64; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
                } else {
                    System.out.println(
                        "Type (mask): INVALID=0; END-USER=1; ADMINISTRATOR=64; SENDNOTIFICATION=256");
                }

                System.out.print("Token      : User Generated=" + SecConst.TOKEN_SOFT_BROWSERGEN +
                    "; P12=" + SecConst.TOKEN_SOFT_P12 + "; JKS=" + SecConst.TOKEN_SOFT_JKS +
                    ";  PEM=" + SecConst.TOKEN_SOFT_PEM);

                if (usehardtokens) {
                    for (int i = 0; i < availabletokens.length; i++) {
                        System.out.print("; " + availabletokens[i].getName() + "=" +
                            availabletokens[i].getId());
                    }
                }

                System.out.print("\n");
                
                
                System.out.print("Existing cas  : ");
                boolean first = true;
                Iterator iter = caids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    System.out.print(", ");                      
                  System.out.print(caidtonamemap.get(iter.next()));
                }
                System.out.print("\n");
                
                System.out.print("Existing certificate profiles  : ");
                first = true;
                iter = certprofileids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    System.out.print(", ");                      
                  System.out.print(certificateprofileidtonamemap.get(iter.next()));
                }
                System.out.print("\n");


                System.out.print("Existing endentity profiles  : ");
                first = true;
                iter = endentityprofileids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    System.out.print(", ");                      
                  System.out.print(endentityprofileidtonamemap.get(iter.next()));
                }
                
                System.out.print("\n");
                if( usehardtokens && hardtokenissueraliases.length > 0){                
                  System.out.print("Existing hardtoken issuers  : ");
                  for(int i=0; i < hardtokenissueraliases.length-1; i++){
                    System.out.print(hardtokenissueraliases[i] + ", ");
                  }
                  System.out.print(hardtokenissueraliases[hardtokenissueraliases.length-1] + "\n");               
                }

                System.out.println(
                    "If the user does not have a SubjectAltName or an email address,\n or you want the password to be auto-generated use the value 'null'. ");
                return;
            }

            String username = args[1];
            String password = args[2];
            String dn = args[3];
            String subjectaltname = args[4];
            String caname  = args[5];
            String email = args[6];
            int type  = Integer.parseInt(args[7]);
            int token = Integer.parseInt(args[8]);
            int profileid =  SecConst.EMPTY_ENDENTITYPROFILE;

            int certificatetypeid = SecConst.CERTPROFILE_FIXED_ENDUSER;
            int hardtokenissuerid = SecConst.NO_HARDTOKENISSUER;
            boolean error = false;
            boolean usehardtokenissuer = false;

            int caid = 0;
            try{
              caid = caadminsession.getCAInfo(administrator, caname).getCAId();
            }catch(Exception e){               
            }
            
            if(args.length == 10){
              // Use certificate type, no end entity profile.
              certificatetypeid = certificatesession.getCertificateProfileId(administrator, args[9]);

            }

            if(args.length == 11){
              // Use certificate type and end entity profile.
              profileid = raadminsession.getEndEntityProfileId(administrator, args[10]);
              certificatetypeid = certificatesession.getCertificateProfileId(administrator, args[9]);
            }

            if(args.length == 12 && usehardtokens){
              // Use certificate type, end entity profile and hardtokenisseur.
              profileid = raadminsession.getEndEntityProfileId(administrator, args[10]);
              certificatetypeid = certificatesession.getCertificateProfileId(administrator, args[9]);
              hardtokenissuerid = hardtokensession.getHardTokenIssuerId(administrator,args[11]);
              usehardtokenissuer = true;
            }
            
            if (!validToken(token, usehardtokens, availabletokens)) {
                System.out.println("Error : Invalid token id.");
                error = true;
            }

            if (certificatetypeid == SecConst.PROFILE_NO_PROFILE) { // Certificate profile not found i database.
                System.out.println("Error : Couldn't find certificate profile in database.");
                error = true;
            }

            if(profileid == 0){ // End entity profile not found i database.
              System.out.println("Error : Couldn't find end entity profile in database." );
              error = true;
            }
            
            if(caid == 0){ // CA not found i database.
              System.out.println("Error : Couldn't find CA in database." );
              error = true;
            }
            
            if(usehardtokenissuer && hardtokenissuerid == SecConst.NO_HARDTOKENISSUER){
              System.out.println("Error : Couldn't find hard token issuer in database." );
              error = true;       
            }  

            if ((token > SecConst.TOKEN_SOFT) &&
                    (hardtokenissuerid == SecConst.NO_HARDTOKENISSUER)) {
                System.out.println(
                    "Error : HardTokenIssuer has to be choosen when user with hard tokens is added.");
                error = true;
            }

            if (email.equalsIgnoreCase("NULL") &&
                    ((type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION)) {
                System.out.println(
                    "Error : Email field cannot be null when send notification type is given.");
                error = true;
            }

            // Check if username already exists.
            try {
                if (getAdminSession().findUser(administrator, username) != null) {
                    ;
                    System.out.println("Error : User already exists in the database.");
                    error = true;
                }
            } catch (FinderException e) {
            }


            if(!error){
              System.out.println("Trying to add user:");
              System.out.println("Username: "+username);
              System.out.println("Password (hashed only): "+password);
              System.out.println("DN: "+dn);
              System.out.println("CA Name: "+caname);
              System.out.println("SubjectAltName: "+subjectaltname);
              System.out.println("Email: "+email);
              System.out.println("Type: "+type);
              System.out.println("Token: "+token);
              System.out.println("Certificate profile: "+certificatetypeid);
              System.out.println("End entity profile: "+profileid);
			  if (password.toUpperCase().equals("NULL"))
				  password = null;
              if (subjectaltname.toUpperCase().equals("NULL"))
                  subjectaltname = null;
              if (email.toUpperCase().equals("NULL"))
                  email = null;
              try{
                getAdminSession().addUser(administrator, username, password, dn, subjectaltname, email, false, profileid, certificatetypeid,
                                         type, token, hardtokenissuerid, caid);
                System.out.println("User '"+username+"' has been added.");
                System.out.println();
                System.out.println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");
              }catch(AuthorizationDeniedException e){
                  System.out.println("Error : " + e.getMessage());
              }catch(UserDoesntFullfillEndEntityProfile e){
                 System.out.println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
              }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
    private boolean validToken(int token, boolean usehardtokens,
        AvailableHardToken[] availabletokens) {
        boolean returnval = false;
        returnval = ((token == SecConst.TOKEN_SOFT_BROWSERGEN) ||
            (token == SecConst.TOKEN_SOFT_P12) || (token == SecConst.TOKEN_SOFT_PEM) ||
            (token == SecConst.TOKEN_SOFT_JKS));

        if (!returnval && usehardtokens) {
            for (int i = 0; i < availabletokens.length; i++) {
                if (token == Integer.parseInt(availabletokens[i].getId())) {
                    returnval = true;

                    break;
                }
            }
        }

        return returnval;
    }
}
