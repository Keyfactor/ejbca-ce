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

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;





/**
 * Adds a user to the database or edits an existing user.
 *
 * @version $Id$
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
	private static final int ARG_STARTTIME          = 14;
	private static final int ARG_ENDTIME            = 15;
	
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
           
            if(args.length < 13 || args.length > 16){
            	usage();
            	System.exit(-1); // NOPMD, this is not a JEE app
            }
            

            UserDataVOWS userdata = new UserDataVOWS();
            userdata.setUsername(args[ARG_USERNAME]);
            String pwd = args[ARG_PASSWORD];
            if (StringUtils.equalsIgnoreCase("null", pwd)) {
            	pwd = null;
            }
            userdata.setPassword(pwd);
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

            if(args.length > 13){
            	if(!args[ARG_ISSUERALIAS].equalsIgnoreCase("NULL")){                        
            		userdata.setHardTokenIssuerName(args[ARG_ISSUERALIAS]);
            	}
            }
            if(args.length > 14){
            	if(!args[ARG_STARTTIME].equalsIgnoreCase("NULL")){                        
            		userdata.setStartTime(args[ARG_STARTTIME]);
            	}
            }
            if(args.length > 15){
            	if(!args[ARG_ENDTIME].equalsIgnoreCase("NULL")){                        
            		userdata.setEndTime(args[ARG_ENDTIME]);
            	}
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
            if(userdata.getStartTime() == null){
                getPrintStream().println("Start time: NONE");
            }else{
                getPrintStream().println("Start time: "+userdata.getStartTime());
            }
            if(userdata.getEndTime() == null){
                getPrintStream().println("End time: NONE");
            }else{
                getPrintStream().println("End time: "+userdata.getEndTime());
            }
            
           try{
            	getEjbcaRAWS().editUser(userdata);

            	
            	getPrintStream().println("User '"+userdata.getUsername()+"' has been added/edited.");
            	getPrintStream().println();              
            }catch(AuthorizationDeniedException_Exception e){
            	getPrintStream().println("Error : " + e.getMessage());
            }catch(UserDoesntFullfillEndEntityProfile_Exception e){
            	getPrintStream().println("Error : Given userdata doesn't fullfill end entity profile. : " +  e.getMessage());
            }
                      
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
		System.exit(-1); // NOPMD, this is not a JEE app
		return 0;
	}

	protected void usage() {
		getPrintStream().println("Command used to add or edit userdata, if user exist will the data be overwritten.");
		getPrintStream().println("Usage : edituser <username> <password|null> <clearpwd (true|false)> <subjectdn> <subjectaltname or NULL> <email or NULL> <caname> <type> <token> <status> <endentityprofilename> <certificateprofilename> <issueralias or NULL (optional)> <starttime or NULL (optional)> <endtime (starttime)>\n\n");
        getPrintStream().println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
        getPrintStream().println(
            "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");

        getPrintStream().println("Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
		
        getPrintStream().print("Existing tokens      : " + "USERGENERATED" + ", " +
        		"P12" + ", "+ "JKS" + ", "  + "PEM" + "\n");
        getPrintStream().print("Existing statuses (new users will always be set as NEW) : NEW, INPROCESS, FAILED, HISTORICAL\n");
        getPrintStream().print("Start time and end time is of form \"May 26, 2009 9:52 AM\" or \"days:hours:minutes\"\n");
	}


}
