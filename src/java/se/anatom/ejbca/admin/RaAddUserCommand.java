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
 
package se.anatom.ejbca.admin;

import java.rmi.RemoteException;
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
import se.anatom.ejbca.ca.store.CertificateDataBean;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionHome;
import se.anatom.ejbca.ca.store.ICertificateStoreSessionRemote;
import se.anatom.ejbca.hardtoken.IHardTokenSessionHome;
import se.anatom.ejbca.hardtoken.IHardTokenSessionRemote;
import se.anatom.ejbca.log.Admin;
import se.anatom.ejbca.ra.raadmin.GlobalConfiguration;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionHome;
import se.anatom.ejbca.ra.raadmin.IRaAdminSessionRemote;
import se.anatom.ejbca.ra.raadmin.UserDoesntFullfillEndEntityProfile;




/**
 * Adds a user to the database.
 *
 * @version $Id: RaAddUserCommand.java,v 1.38 2005-04-27 09:55:34 anatom Exp $
 */
public class RaAddUserCommand extends BaseRaAdminCommand {
	
	private static final String USERGENERATED = "USERGENERATED"; 
	private static final String P12           = "P12";
	private static final String JKS           = "JKS";
	private static final String PEM           = "PEM";
	
	private final String[] softtokennames = {USERGENERATED,P12,JKS,PEM};
	private final int[] softtokenids = {SecConst.TOKEN_SOFT_BROWSERGEN,
			SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM};
	
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
            InitialContext jndicontext = getInitialContext();

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
            Collection authorizedhardtokenprofiles   = null;
            HashMap hardtokenprofileidtonamemap = null;            

            IHardTokenSessionRemote hardtokensession=null;
            if(usehardtokens){  
              IHardTokenSessionHome hardtokensessionhome = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(jndicontext.lookup("HardTokenSession"),
                                                                                 IHardTokenSessionHome.class);
              hardtokensession = hardtokensessionhome.create();
              hardtokenissueraliases = (String[]) hardtokensession.getHardTokenIssuerAliases(administrator).toArray((Object[]) new String[0]);             

              authorizedhardtokenprofiles = hardtokensession.getAuthorizedHardTokenProfileIds(administrator);
              hardtokenprofileidtonamemap = hardtokensession.getHardTokenProfileIdToNameMap(administrator);
            }  
            
            if (args.length < 9) {
                Collection certprofileids = certificatesession.getAuthorizedCertificateProfileIds(administrator, CertificateDataBean.CERTTYPE_ENDENTITY);
                HashMap certificateprofileidtonamemap = certificatesession.getCertificateProfileIdToNameMap(administrator);
                
                Collection endentityprofileids =  raadminsession.getAuthorizedEndEntityProfileIds(administrator);
                HashMap endentityprofileidtonamemap = raadminsession.getEndEntityProfileIdToNameMap(administrator);
                
                Collection caids = authorizationsession.getAuthorizedCAIds(administrator);
                HashMap caidtonamemap = caadminsession.getCAIdToNameMap(administrator);
                
                if( usehardtokens)
                  getOutputStream().println("Usage: RA adduser <username> <password> <dn> <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] [<hardtokenissuer>]");
                else
                  getOutputStream().println("Usage: RA adduser <username> <password> <dn> <subjectAltName> <caname> <email> <type> <token> [<certificateprofile>]  [<endentityprofile>] ");


                getOutputStream().println("");
                getOutputStream().println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
                getOutputStream().println(
                    "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");

                if (usekeyrecovery) {
                    getOutputStream().println(
                        "Type (mask): INVALID=0; END-USER=1; ADMINISTRATOR=64; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
                } else {
                    getOutputStream().println(
                        "Type (mask): INVALID=0; END-USER=1; ADMINISTRATOR=64; SENDNOTIFICATION=256");
                }

                getOutputStream().print("Existing tokens      : " + USERGENERATED + ", " +
                                          P12 + ", "+ JKS + ", "  + PEM);

                if (usehardtokens) {
                  Iterator iter = authorizedhardtokenprofiles.iterator();
                  while(iter.hasNext()){
                    getOutputStream().print(", " + hardtokenprofileidtonamemap.get(iter.next()));
                  }
                }

                getOutputStream().print("\n");
                
                
                getOutputStream().print("Existing cas  : ");
                boolean first = true;
                Iterator iter = caids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    getOutputStream().print(", ");                      
                  getOutputStream().print(caidtonamemap.get(iter.next()));
                }
                getOutputStream().print("\n");
                
                getOutputStream().print("Existing certificate profiles  : ");
                first = true;
                iter = certprofileids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    getOutputStream().print(", ");                      
                  getOutputStream().print(certificateprofileidtonamemap.get(iter.next()));
                }
                getOutputStream().print("\n");


                getOutputStream().print("Existing endentity profiles  : ");
                first = true;
                iter = endentityprofileids.iterator();
                while(iter.hasNext()){
                  if(first)                    
                    first= false;
                  else
                    getOutputStream().print(", ");                      
                  getOutputStream().print(endentityprofileidtonamemap.get(iter.next()));
                }
                
                getOutputStream().print("\n");
                if( usehardtokens && hardtokenissueraliases.length > 0){                
                  getOutputStream().print("Existing hardtoken issuers  : ");
                  for(int i=0; i < hardtokenissueraliases.length-1; i++){
                    getOutputStream().print(hardtokenissueraliases[i] + ", ");
                  }
                  getOutputStream().print(hardtokenissueraliases[hardtokenissueraliases.length-1] + "\n");               
                }

                getOutputStream().println(
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
            String tokenname = args[8];
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
            
            int tokenid =getTokenId(administrator, tokenname, usehardtokens, hardtokensession);
            if (tokenid == 0) {
                getOutputStream().println("Error : Invalid token id.");
                error = true;
            }

            if (certificatetypeid == SecConst.PROFILE_NO_PROFILE) { // Certificate profile not found i database.
                getOutputStream().println("Error : Couldn't find certificate profile in database.");
                error = true;
            }

            if(profileid == 0){ // End entity profile not found i database.
              getOutputStream().println("Error : Couldn't find end entity profile in database." );
              error = true;
            }
            
            if(caid == 0){ // CA not found i database.
              getOutputStream().println("Error : Couldn't find CA in database." );
              error = true;
            }
            
            if(usehardtokenissuer && hardtokenissuerid == SecConst.NO_HARDTOKENISSUER){
              getOutputStream().println("Error : Couldn't find hard token issuer in database." );
              error = true;       
            }  

            if ((tokenid > SecConst.TOKEN_SOFT) &&
                    (hardtokenissuerid == SecConst.NO_HARDTOKENISSUER)) {
                getOutputStream().println(
                    "Error : HardTokenIssuer has to be choosen when user with hard tokens is added.");
                error = true;
            }

            if (email.equalsIgnoreCase("NULL") &&
                    ((type & SecConst.USER_SENDNOTIFICATION) == SecConst.USER_SENDNOTIFICATION)) {
                getOutputStream().println(
                    "Error : Email field cannot be null when send notification type is given.");
                error = true;
            }

            // Check if username already exists.
            try {
                if (getAdminSession().findUser(administrator, username) != null) {
                    getOutputStream().println("Error : User already exists in the database.");
                    error = true;
                }
            } catch (FinderException e) {
            }


            if(!error){
              getOutputStream().println("Trying to add user:");
              getOutputStream().println("Username: "+username);
              getOutputStream().println("Password (hashed only): "+password);
              getOutputStream().println("DN: "+dn);
              getOutputStream().println("CA Name: "+caname);
              getOutputStream().println("SubjectAltName: "+subjectaltname);
              getOutputStream().println("Email: "+email);
              getOutputStream().println("Type: "+type);
              getOutputStream().println("Token: "+tokenname);
              getOutputStream().println("Certificate profile: "+certificatetypeid);
              getOutputStream().println("End entity profile: "+profileid);
			  if (password.toUpperCase().equals("NULL"))
				  password = null;
              if (subjectaltname.toUpperCase().equals("NULL"))
                  subjectaltname = null;
              if (email.toUpperCase().equals("NULL"))
                  email = null;
              try{
                getAdminSession().addUser(administrator, username, password, dn, subjectaltname, email, false, profileid, certificatetypeid,
                                         type, tokenid, hardtokenissuerid, caid);
                getOutputStream().println("User '"+username+"' has been added.");
                getOutputStream().println();
                getOutputStream().println("Note: If batch processing should be possible, \nalso use 'ra setclearpwd "+username+" <pwd>'.");
              }catch(AuthorizationDeniedException e){
                  getOutputStream().println("Error : " + e.getMessage());
              }catch(UserDoesntFullfillEndEntityProfile e){
                 getOutputStream().println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
              }
            }
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

    // execute
    /**
     *  Returns the tokenid type of the user, returns 0 if invalid tokenname.    
     */
    
    private int getTokenId(Admin administrator, String tokenname, boolean usehardtokens, IHardTokenSessionRemote hardtokensession) throws RemoteException {
        int returnval = 0;
        
        // First check for soft token type
        for(int i=0;i< softtokennames.length;i++){
        	if(softtokennames[i].equals(tokenname)){
        		returnval = softtokenids[i];
        		break;
        	}        	
        }

        if (returnval == 0 && usehardtokens) {
             returnval = hardtokensession.getHardTokenProfileId(administrator , tokenname);
        }

        return returnval;
    }
}
