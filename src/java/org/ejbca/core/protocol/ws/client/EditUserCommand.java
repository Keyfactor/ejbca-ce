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
 
package org.ejbca.core.protocol.ws.client;

import org.ejbca.core.model.SecConst;
//import org.ejbca.core.model.authorization.wsclient.AuthorizationDeniedException;
import org.ejbca.core.model.ra.UserDataConstants;
//import org.ejbca.core.model.ra.raadmin.wsclient.UserDoesntFullfillEndEntityProfile;
//import org.ejbca.core.protocol.ws.wsclient.UserDataVOWS;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;





/**
 * Adds a user to the database.
 *
 * @version $Id: EditUserCommand.java,v 1.1 2006-09-17 23:00:25 herrvendil Exp $
 */
public class EditUserCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
	private static final int ARG_USERNAME           = 1;
	private static final int ARG_PASSWORD           = 2;
	private static final int ARG_CLEARPWD           = 3;
	private static final int ARG_SUBJECTDN          = 4;
	private static final int ARG_SUBJECTALTNAME     = 5;
	private static final int ARG_EMAIL              = 6;
	private static final int ARG_CA                 = 7;
	private static final int ARG_TYPE               = 8;
	private static final int ARG_TOKEN              = 9;
	private static final int ARG_STATUS             = 10;
	private static final int ARG_ENDENTITYPROFILE   = 11;
	private static final int ARG_CERTIFICATEPROFILE = 12;
	private static final int ARG_ISSUERALIAS        = 13;
	
    /**
     * Creates a new instance of RaAddUserCommand
     *
     * @param args command line arguments
     */
    public EditUserCommand(String[] args) {
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
           
            if(args.length < 13 || args.length > 14){
            	usage();
            	System.exit(-1);
            }
            
            String msg = getEjbcaRAWS().test("bla");
            if(msg.equals("bla")){
            	System.out.println("messages are equal");
            }else{
            	System.out.println("messages are NOT equal");
            }
            /*
            UserDataVOWS userdata = new UserDataVOWS();
            userdata.setUsername(args[ARG_USERNAME]);
            userdata.setPassword(args[ARG_PASSWORD]);
            userdata.setClearPwd(args[ARG_CLEARPWD].equalsIgnoreCase("true"));
            userdata.setSubjectDN(args[ARG_SUBJECTDN]);
            if(!args[ARG_SUBJECTALTNAME].equalsIgnoreCase("NULL")){                        
            	userdata.setSubjectAltName(args[ARG_SUBJECTALTNAME]);
            }
            if(!args[ARG_EMAIL].equalsIgnoreCase("NULL")){
            	userdata.setEmail(args[ARG_EMAIL]);
            }
            userdata.setCaName(args[ARG_CA]);
            userdata.setTokenType(args[ARG_TOKEN]);
            userdata.setStatus(getStatus(args[ARG_STATUS]));
            userdata.setEndEntityProfileName(args[ARG_ENDENTITYPROFILE]);
            userdata.setCertificateProfileName(args[ARG_CERTIFICATEPROFILE]);
            
            int type = Integer.parseInt(args[ARG_TYPE]);
            
            if((type & SecConst.USER_SENDNOTIFICATION) != 0){
            	userdata.setSendNotification(true);
            }
            if((type & SecConst.USER_KEYRECOVERABLE) != 0){
            	userdata.setKeyRecoverable(true);
            }

            if(args.length == 14){
              userdata.setHardTokenIssuerName(args[ARG_ISSUERALIAS]);
            }
   
            getPrintStream().println("Trying to add user:");
            getPrintStream().println("Username: "+userdata.getUsername());
            getPrintStream().println("Subject DN: "+userdata.getSubjectDN());
            getPrintStream().println("Subject Altname: "+userdata.getSubjectAltName());
            getPrintStream().println("Email: "+userdata.getEmail());
            getPrintStream().println("CA Name: "+userdata.getCaName());                        
            getPrintStream().println("Type: "+type);
            getPrintStream().println("Token: "+userdata.getTokenType());
            getPrintStream().println("Status: "+userdata.getStatus());
            getPrintStream().println("End entity profile: "+userdata.getEndEntityProfileName());
            getPrintStream().println("Certificate profile: "+userdata.getCertificateProfileName());

            if(userdata.getHardTokenIssuerName() == null){
            	getPrintStream().println("Hard Token Issuer Alias: NONE");
            }else{
            	getPrintStream().println("Hard Token Issuer Alias: " + userdata.getHardTokenIssuerName());
            }
            
            
            try{
            	getEjbcaRAWS().editUser(userdata);

            	
            	getPrintStream().println("User '"+userdata.getUsername()+"' has been added/edited.");
            	getPrintStream().println();              
            }catch(AuthorizationDeniedException e){
            	getPrintStream().println("Error : " + e.getMessage());
            }catch(UserDoesntFullfillEndEntityProfile e){
            	getPrintStream().println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
            }
            */            
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }

	private int getStatus(String status) {
		if(status.equalsIgnoreCase("NEW")){
			return UserDataConstants.STATUS_NEW;
		}
		if(status.equalsIgnoreCase("INPROCESS")){
			return UserDataConstants.STATUS_INPROCESS;
		}
		if(status.equalsIgnoreCase("FAILED")){
			return UserDataConstants.STATUS_FAILED;
		}
		if(status.equalsIgnoreCase("HISTORICAL")){
			return UserDataConstants.STATUS_HISTORICAL;
		}		
		
		getPrintStream().println("Error in status string : " + status );
		usage();
		System.exit(-1);
		return 0;
	}

	protected void usage() {
		getPrintStream().println("Command used to add or edit userdata, if user exist will the data be overwritten.");
		getPrintStream().println("Usage : edituser <username> <password> <clearpwd (true|false)> <subjectdn> <subjectaltname or NULL> <email or NULL> <caname> <type> <token> <status> <endentityprofilename> <certificateprofilename> <issueralias (Optional)> \n\n");
        getPrintStream().println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
        getPrintStream().println(
            "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");

        getPrintStream().println("Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
		
        getPrintStream().print("Existing tokens      : " + "USERGENERATED" + ", " +
        		"P12" + ", "+ "JKS" + ", "  + "PEM");
        getPrintStream().print("Existing statuses (new users will always be set as NEW) : NEW, INPROCESS, FAILED, HISTORICAL");
	}


}
