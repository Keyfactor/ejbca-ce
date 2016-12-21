/*************************************************************************
 *                                                                       *
 *  EJBCA Community: The OpenSource Certificate Authority                *
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

import java.math.BigInteger;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
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

	private static final int NR_OF_MANDATORY_ARGS = ARG_CERTIFICATEPROFILE+1;
	private static final int MAX_NR_OF_ARGS = ARG_ENDTIME+1;

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
    	
        final UserDataVOWS userdata = new UserDataVOWS();
        final String[] myArgs = ParseUserData.getDataFromArgs(this.args, userdata, getPrintStream());
    	if(myArgs.length < NR_OF_MANDATORY_ARGS || myArgs.length > MAX_NR_OF_ARGS){
        	usage();
        	System.exit(-1); // NOPMD, this is not a JEE app
        }
        try {
            userdata.setUsername(myArgs[ARG_USERNAME]);
            String pwd = myArgs[ARG_PASSWORD];
            if (StringUtils.equalsIgnoreCase("null", pwd)) {
            	pwd = null;
            }
            userdata.setPassword(pwd);
            userdata.setClearPwd(myArgs[ARG_CLEARPWD].equalsIgnoreCase("true"));
            userdata.setSubjectDN(myArgs[ARG_SUBJECTDN]);
            if(!myArgs[ARG_SUBJECTALTNAME].equalsIgnoreCase("NULL")){                        
            	userdata.setSubjectAltName(myArgs[ARG_SUBJECTALTNAME]);
            }
            if(!myArgs[ARG_EMAIL].equalsIgnoreCase("NULL")){
            	userdata.setEmail(myArgs[ARG_EMAIL]);
            }
            userdata.setCaName(myArgs[ARG_CA]);
            userdata.setTokenType(myArgs[ARG_TOKEN]);
            userdata.setStatus(getStatus(myArgs[ARG_STATUS]));
            userdata.setEndEntityProfileName(myArgs[ARG_ENDENTITYPROFILE]);
            userdata.setCertificateProfileName(myArgs[ARG_CERTIFICATEPROFILE]);
            
            EndEntityType type = new EndEntityType(EndEntityTypes.getTypesFromHexCode(Integer.parseInt(myArgs[ARG_TYPE])));
            
            if(type.contains(EndEntityTypes.SENDNOTIFICATION)){
            	userdata.setSendNotification(true);
            }
            if(type.contains(EndEntityTypes.KEYRECOVERABLE)){
            	userdata.setKeyRecoverable(true);
            }

            if(myArgs.length > ARG_ISSUERALIAS){
            	if(!myArgs[ARG_ISSUERALIAS].equalsIgnoreCase("NULL")){                        
            		userdata.setHardTokenIssuerName(myArgs[ARG_ISSUERALIAS]);
            	}
            }
            if(myArgs.length > ARG_STARTTIME){
            	if(!myArgs[ARG_STARTTIME].equalsIgnoreCase("NULL")){                        
            		userdata.setStartTime(myArgs[ARG_STARTTIME]);
            	}
            }
            if(myArgs.length > ARG_ENDTIME){
            	if(!myArgs[ARG_ENDTIME].equalsIgnoreCase("NULL")){                        
            		userdata.setEndTime(myArgs[ARG_ENDTIME]);
            	}
            }
   
            getPrintStream().println("Trying to add user:");
            getPrintStream().println("Username: "+userdata.getUsername());
            getPrintStream().println("Subject DN: "+userdata.getSubjectDN());
            getPrintStream().println("Subject Altname: "+userdata.getSubjectAltName());
            getPrintStream().println("Email: "+userdata.getEmail());
            getPrintStream().println("CA Name: "+userdata.getCaName());                        
            getPrintStream().println("Type: "+type.getHexValue());
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
            {
            	final List<ExtendedInformationWS> eil = userdata.getExtendedInformation();
            	if ( eil!=null ) {
            		getPrintStream().println("Extended information:");
            		for ( ExtendedInformationWS ei : eil ) {
            			getPrintStream().println("	'"+ei.getName()+"' = '"+ei.getValue()+"'");
            		}
            	}
            }
            {
            	final BigInteger bi = userdata.getCertificateSerialNumber();
            	if ( bi!=null ) {
                    getPrintStream().println(ParseUserData.certificateSerialNumber+"=0x"+bi.toString(16));
            	}
            }
            
           try{
            	getEjbcaRAWS().editUser(userdata);

            	
            	getPrintStream().println("User '"+userdata.getUsername()+"' has been added/edited.");
            	getPrintStream().println();              
            }catch(AuthorizationDeniedException_Exception e){
            	getPrintStream().println("Error : " + e.getMessage());
            }catch(UserDoesntFullfillEndEntityProfile_Exception e){
            	getPrintStream().println("Error : Given userdata doesn't fulfill end entity profile. : " +  e.getMessage());
            }
                      
        } catch (Exception e) {
            throw new ErrorAdminCommandException(e);
        }
    }
    private int getStatus(String status) {
		if(status.equalsIgnoreCase("NEW")){
			return EndEntityConstants.STATUS_NEW;
		}
		if(status.equalsIgnoreCase("INPROCESS")){
			return EndEntityConstants.STATUS_INPROCESS;
		}
		if(status.equalsIgnoreCase("FAILED")){
			return EndEntityConstants.STATUS_FAILED;
		}
		if(status.equalsIgnoreCase("HISTORICAL")){
			return EndEntityConstants.STATUS_HISTORICAL;
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
        getPrintStream().println("SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");
        getPrintStream().println("Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
        getPrintStream().println("Existing tokens: USERGENERATED, P12, JKS, PEM");
        getPrintStream().println("Existing statuses (new users will always be set as NEW) : NEW, INPROCESS, FAILED, HISTORICAL");
        getPrintStream().println("Start time and end time is of form \"May 26, 2009 9:52 AM\" or \"days:hours:minutes\"");
        getPrintStream().println();
        ParseUserData.printCliHelp(getPrintStream());
	}


}
