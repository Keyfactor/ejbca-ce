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
 
package org.ejbca.ui.cli;

import java.io.BufferedReader;
import java.io.FileReader;
import java.util.ArrayList;

import javax.naming.Context;
import javax.naming.NamingException;

import org.ejbca.core.ejb.authorization.IAuthorizationSessionHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionRemote;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionRemote;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionRemote;
import org.ejbca.core.ejb.ra.IUserAdminSessionHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionRemote;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionRemote;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AdminEntity;
import org.ejbca.core.model.hardtoken.HardTokenIssuer;
import org.ejbca.core.model.hardtoken.profiles.IPINEnvelopeSettings;
import org.ejbca.core.model.hardtoken.profiles.SwedishEIDProfile;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.raadmin.EndEntityProfile;
import org.ejbca.core.model.ra.raadmin.GlobalConfiguration;

/** Class used for easy setup primecard server.
 *  
 *  This isn't used as a commande line but used from withing it's run by the command
 *  ejbca.sh/cmd setup initializehardtokenissuing
 * 
 *  It's main method run sets up:
 * 1.  Sets the global setting use hard token funtionality to true.
 * 2.  A default 'Administrator Token' Hard Profile Token
 * 3.  A default 'Local' Hard Token Issuer with the 'Temporate Super Admin Group' as admin group. 
 * 4.  Adds a 'Administrator Token End Entity Profile' End Entity Profile with the following fields:
 *    * CN, required
 *    * 'Administrator Token' as default and available tokens
 *    * 'local' as default and available issuers
 *    * default available CA is taken from parameter to run method
 * 
 * 5. Adds a user SuperAdminToken with CN=SuperAdminToken with issuer local
 * 6. Adds SuperAdminToken to Temporate Super Admin Group
 * 
 * After run have been executed should it be easy to run primecard locally to just issue the first card.
 * 
 * @author Philip Vendil
 * @version $Id: InitializeHardTokenIssuing.java,v 1.2 2006-06-08 14:45:04 anatom Exp $
 *
 */
public class InitializeHardTokenIssuing extends BaseAdminCommand {
     
	private static final String SVGPINFILENAME = "src/cli/admincard_pintemplate.svg";
	
	private static final String ADMINTOKENPROFILENAME = "Administrator Token Profile";
	
	private static final String ISSUERALIAS = "local";
	
	private static final String SUPERADMINTOKENNAME = "SuperAdminToken";
	
	private static final String ADMINTOKENENDENTITYPROFILE = "Administration Token End Entity Profile";
		
	private IRaAdminSessionRemote raadminsession;
	private IAuthorizationSessionRemote authorizationsession;
	private IHardTokenSessionRemote hardtokensession;
	private IUserAdminSessionRemote useradminsession;

	private ICAAdminSessionRemote caadminsession;
    
	
	
	public InitializeHardTokenIssuing(String[]  args){
	  super(args, Admin.TYPE_CACOMMANDLINE_USER);
	}			
	
	public void execute() throws IllegalAdminCommandException, ErrorAdminCommandException{
        if (args.length < 2) {
 	       throw new IllegalAdminCommandException("Usage: SETUP initializehardtokenissuing <caname>\n"); 
 	       		                                                               	       
 	    }	
        String caname = args[1];
        try{
	      runSetup(caname);
        }catch(Exception e){
	      throw new ErrorAdminCommandException(e);
	    }
	}
					
	
	
	/**
	 * See class header for explaination.
	 * 
	 */				
	private void runSetup(String caname) throws Exception{
		getOutputStream().println("Adding Hard Token Super Administrator .....\n\n");
		int caid = this.getCAAdminSession().getCAInfo(administrator, caname).getCAId();
		int admingroupid  = getAuthorizationSession().getAdminGroup(administrator, "Temporary Super Administrator Group", caid).getAdminGroupId();
		
		configureGlobalConfiguration();
		createAdministratorTokenProfile();
		createLocalHardTokenIssuer(caid, admingroupid);
		createAdminTokenEndEntityProfile(caid);
		createSuperAdminTokenUser(caid);
		addSuperAdminTokenUserToTemporarySuperAdminGroup(caid);
		
		getOutputStream().print("A hard token Administrator have been added.\n\n" +
				         "In order to issue the card. Startup PrimeCard in local mode using\n" +
						 "the alias 'local'. Then insert an empty token.\n" + 
				         "This Administrator is also a super administrator for the EJBCA installation.\n");
	}
	
    /**
     * Sets the Issue Hard Tokens flag to true in the system configuration.
     * 
     * @throws Exception
     */
	private void configureGlobalConfiguration() throws Exception{
	  GlobalConfiguration config = getRAAdminSession().loadGlobalConfiguration(administrator);
	  config.setIssueHardwareTokens(true);
	  this.getRAAdminSession().saveGlobalConfiguration(administrator, config);
	}
	
    /**
     * Creates the 'Administrator Token' Hard Token Profile
     * 
     * @throws Exception
     */
	private void createAdministratorTokenProfile() throws Exception{
	  SwedishEIDProfile admintokenprofile = new SwedishEIDProfile();
	  
	  admintokenprofile.setPINEnvelopeType(IPINEnvelopeSettings.PINENVELOPETYPE_GENERALENVELOBE);
	  
	  BufferedReader br = new BufferedReader(new FileReader(SVGPINFILENAME));
	  String filecontent = "";
	  String nextline = "";
	  while(nextline!=null){
	  	nextline = br.readLine();
	  	if(nextline != null)				    
	  		filecontent += nextline + "\n";
	  }
	  ((IPINEnvelopeSettings) admintokenprofile).setPINEnvelopeData(filecontent);
	  ((IPINEnvelopeSettings) admintokenprofile).setPINEnvelopeTemplateFilename(SVGPINFILENAME);	  
	  
	  this.getHardTokenSession().addHardTokenProfile(administrator,ADMINTOKENPROFILENAME, admintokenprofile);
	}
	
    /**
     * Creates the 'Local' Hard Token Issuer
     * 
     * @throws Exception
     */
	private void createLocalHardTokenIssuer(int caid, int admingroupid) throws Exception{
	  HardTokenIssuer localissuer = new HardTokenIssuer();
	  
	  localissuer.setDescription("Issuer created by installation script, used to create the first administration token");
	  
	  ArrayList availableprofiles = new ArrayList();
	  availableprofiles.add(new Integer(getHardTokenSession().getHardTokenProfileId(administrator, ADMINTOKENPROFILENAME)));	  
	  localissuer.setAvailableHardTokenProfiles(availableprofiles);
	  	  	  
	  this.getHardTokenSession().addHardTokenIssuer(administrator, ISSUERALIAS, admingroupid, localissuer);
	  	  
	}

    /**
     * Creates the End Entity Profile used for issuing the superadmintoken
     * 
     * @throws Exception
     */
	private void createAdminTokenEndEntityProfile(int caid) throws Exception {
	  int tokenid = getHardTokenSession().getHardTokenProfileId(administrator, ADMINTOKENPROFILENAME);
	  int hardtokenissuerid = getHardTokenSession().getHardTokenIssuerId(administrator, ISSUERALIAS);
	  EndEntityProfile profile = new EndEntityProfile();
	  
	  // Set autogenerated password
	  profile.setUse(EndEntityProfile.PASSWORD,0,false);
	  
	  // Batch
	  profile.setUse(EndEntityProfile.CLEARTEXTPASSWORD,0,true);
	  profile.setRequired(EndEntityProfile.CLEARTEXTPASSWORD,0,true);
	  profile.setValue(EndEntityProfile.CLEARTEXTPASSWORD,0,EndEntityProfile.TRUE);
	  
	  // Set CA
      profile.setValue(EndEntityProfile.DEFAULTCA,0,"" + caid);	  
      profile.setValue(EndEntityProfile.AVAILCAS,0,"" + caid);
      
      profile.setValue(EndEntityProfile.DEFAULTCERTPROFILE,0,"" + SecConst.CERTPROFILE_FIXED_ENDUSER);	  
      profile.setValue(EndEntityProfile.AVAILCERTPROFILES,0,"" + SecConst.CERTPROFILE_FIXED_ENDUSER + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENAUTH 
      		                                                   + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENAUTHENC + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENSIGN
															   + ";" + SecConst.CERTPROFILE_FIXED_HARDTOKENENC);
      
	  // Set Default Token Type
	  profile.setValue(EndEntityProfile.DEFKEYSTORE,0,"" + tokenid);
	  profile.setValue(EndEntityProfile.AVAILKEYSTORE,0,"" + tokenid);	  	  
	  
	  // Set Default Issuers
	  profile.setUse(EndEntityProfile.AVAILTOKENISSUER,0,true);
	  
	  profile.setValue(EndEntityProfile.DEFAULTTOKENISSUER,0,"" + hardtokenissuerid);
      profile.setValue(EndEntityProfile.AVAILTOKENISSUER,0,"" + hardtokenissuerid);
	  
	  // Set Administrator Flag
	  profile.setUse(EndEntityProfile.ADMINISTRATOR,0,true);
	  profile.setRequired(EndEntityProfile.ADMINISTRATOR,0,true);
	  profile.setValue(EndEntityProfile.ADMINISTRATOR,0,EndEntityProfile.TRUE);
	  	  
	  // Save Profile
	  this.getRAAdminSession().addEndEntityProfile(administrator, ADMINTOKENENDENTITYPROFILE, profile);
	}
	
    /**
     * Adds a new superadmintoken user to the user database and puts it to the local issuer queue.
     * 
     * @throws Exception
     */
	private void createSuperAdminTokenUser(int caid) throws Exception{
		int endentityprofileid = getRAAdminSession().getEndEntityProfileId(administrator, ADMINTOKENENDENTITYPROFILE); 
		int certificateprofileid = SecConst.CERTPROFILE_FIXED_ENDUSER;
		int tokenid = getHardTokenSession().getHardTokenProfileId(administrator, ADMINTOKENPROFILENAME);
		int hardtokenissuerid = getHardTokenSession().getHardTokenIssuerId(administrator, ISSUERALIAS);
		
		this.getUserAdminSession().addUser(administrator,SUPERADMINTOKENNAME, null, "CN=" + SUPERADMINTOKENNAME,
				                           null,null,true, endentityprofileid, certificateprofileid, 65, 
				                           tokenid, hardtokenissuerid, caid);   								
	}

    /**
     * Adds the new superadmintoken user to the Temporary Super Admin Group
     * 
     * @throws Exception
     */	
	private void addSuperAdminTokenUserToTemporarySuperAdminGroup(int caid) throws Exception{		
		ArrayList adminentities = new ArrayList();
		adminentities.add(new AdminEntity(AdminEntity.WITH_COMMONNAME,AdminEntity.TYPE_EQUALCASEINS,SUPERADMINTOKENNAME,caid));		
		getAuthorizationSession().addAdminEntities(administrator, "Temporary Super Administrator Group", caid, adminentities);		
	}
	
	
	private IHardTokenSessionRemote getHardTokenSession() throws Exception{
		debug(">getHardTokenSession()");
        try {
            if( hardtokensession == null ) {                
               Context jndiContext = getInitialContext();
               Object obj1 = jndiContext.lookup("HardTokenSession");
               IHardTokenSessionHome homesession = (IHardTokenSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IHardTokenSessionHome.class);                
               hardtokensession = homesession.create();
            }
            debug("<getHardTokenSession()");
            return  hardtokensession;
        } catch (NamingException e ) {
            error("Can't get hardtoken session", e);
            throw e;
        }
	}
	
	private IRaAdminSessionRemote getRAAdminSession() throws Exception{
		debug(">getRaAdminSession()");
        try {
            if( raadminsession == null ) {                
               Context jndiContext = getInitialContext();
               Object obj1 = jndiContext.lookup("RaAdminSession");
               IRaAdminSessionHome raadminHomesession = (IRaAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IRaAdminSessionHome.class);                
                raadminsession = raadminHomesession.create();
            }
            debug("<getRaAdminSession()");
            return  raadminsession;
        } catch (NamingException e ) {
            error("Can't get RaAdmin session", e);
            throw e;
        }		
	}
	
	private IAuthorizationSessionRemote getAuthorizationSession() throws Exception{
		debug(">getAuthorizationSession()");
        try {
            if( authorizationsession == null ) {                
               Context jndiContext = getInitialContext();
               Object obj1 = jndiContext.lookup("AuthorizationSession");
               IAuthorizationSessionHome homesession = (IAuthorizationSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IAuthorizationSessionHome.class);                
               authorizationsession = homesession.create();
            }
            debug("<getAuthorizationSession()");
            return  authorizationsession;
        } catch (NamingException e ) {
            error("Can't get authorization session", e);
            throw e;
        }	
	}
	
	private IUserAdminSessionRemote getUserAdminSession() throws Exception{
		debug(">getUserAdminSession()");
        try {
            if( useradminsession == null ) {                
               Context jndiContext = getInitialContext();
               Object obj1 = jndiContext.lookup("UserAdminSession");
               IUserAdminSessionHome homesession = (IUserAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, IUserAdminSessionHome.class);                
               useradminsession = homesession.create();
            }
            debug("<getUserAdminSession()");
            return  useradminsession;
        } catch (NamingException e ) {
            error("Can't get user admin session", e);
            throw e;
        }	
	}
	
	private ICAAdminSessionRemote getCAAdminSession() throws Exception{
		debug(">getCAAdminSession()");
        try {
            if( caadminsession == null ) {                
               Context jndiContext = getInitialContext();
               Object obj1 = jndiContext.lookup("CAAdminSession");
               ICAAdminSessionHome homesession = (ICAAdminSessionHome) javax.rmi.PortableRemoteObject.narrow(obj1, ICAAdminSessionHome.class);                
               caadminsession = homesession.create();
            }
            debug("<getCAAdminSession()");
            return  caadminsession;
        } catch (NamingException e ) {
            error("Can't get user admin session", e);
            throw e;
        }	
	}
			
}
