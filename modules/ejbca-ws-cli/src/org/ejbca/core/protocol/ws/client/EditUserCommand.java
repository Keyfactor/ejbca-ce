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

import java.math.BigInteger;
import java.util.LinkedList;
import java.util.List;

import org.apache.commons.lang.StringUtils;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;
import org.ejbca.util.cert.OID;





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
	private static final String certificateSerialNumber="CERTIFICATESERIALNUMBER";
	private static final String hexPrefix = "0x";
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
    	
        final UserDataVOWS userdata = new UserDataVOWS();
        final String[] myArgs = setExtensionData(this.args, userdata);
        if ( myArgs==null ) {
        	System.exit(-1);// problem with extension data. User info printed by setExtensionData
        }
        try {
        	
        	if(myArgs.length < NR_OF_MANDATORY_ARGS || myArgs.length > MAX_NR_OF_ARGS){
            	usage();
            	System.exit(-1); // NOPMD, this is not a JEE app
            }
            

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
            
            int type = Integer.parseInt(myArgs[ARG_TYPE]);
            
            if((type & SecConst.USER_SENDNOTIFICATION) != 0){
            	userdata.setSendNotification(true);
            }
            if((type & SecConst.USER_KEYRECOVERABLE) != 0){
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
            		getPrintStream().println(certificateSerialNumber+"="+bi.toString());
            	}
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
	private String[] setExtensionData(String args[], UserDataVOWS userData) {
		final List<ExtendedInformationWS> lei = new LinkedList<ExtendedInformationWS>();
		final List<String> lArgs = new LinkedList<String>();
		for ( int i=0; i<args.length; i++ ) {
			final String arg = args[i];
			final int equalPos = arg.indexOf('=');
			if ( equalPos<0 || equalPos+1>arg.length() ) {
				lArgs.add(arg);
				continue;
			}
			final String key = arg.substring(0, equalPos).trim();
			final String value = arg.substring(equalPos+1,arg.length()).trim();
			if ( key.equalsIgnoreCase(certificateSerialNumber) ) {
				final boolean isHex = value.substring(0, hexPrefix.length()).equalsIgnoreCase(hexPrefix);
				final BigInteger nr;
				try {
					nr = isHex ? new BigInteger(value.substring(hexPrefix.length()), 16) : new BigInteger(value);
				} catch( NumberFormatException e ) {
					getPrintStream().println(certificateSerialNumber+" '"+value+"' is not a valid number");
					return null;
				}
				userData.setCertificateSerialNumber(nr);
				continue;
			}
			if ( OID.isStartingWithValidOID(key) ) {
				lei.add(new ExtendedInformationWS(key, value));
				continue;				
			}
			lArgs.add(arg);
		}
		if ( lei.size()>0 ) {
			userData.setExtendedInformation(lei);
		}
		return lArgs.toArray(new String[0]);
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
        getPrintStream().println("SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");
        getPrintStream().println("Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
        getPrintStream().println("Existing tokens: USERGENERATED, P12, JKS, PEM");
        getPrintStream().println("Existing statuses (new users will always be set as NEW) : NEW, INPROCESS, FAILED, HISTORICAL");
        getPrintStream().println("Start time and end time is of form \"May 26, 2009 9:52 AM\" or \"days:hours:minutes\"");
        getPrintStream().println();
        getPrintStream().println("Certificate serial number and certificate extension may be added as extra parameters. These parameters may be inserted at any position since they are removed before the other parameters (above) are parsed.");
        getPrintStream().println("For certificate serial number the parameter looks like this '"+certificateSerialNumber+"=<serial number>'. Start the number with '"+hexPrefix+"' to indicated that it is hexadecimal. Example: "+certificateSerialNumber+"=8642378462375036 "+certificateSerialNumber+"=0x5a53875acdaf24");
        getPrintStream().println("For certificate extension the parameter look like this '<oid>[.<type>]=value'. The key '1.2.3.4' is same as '1.2.3.4.value'. Example: 1.2.840.113634.100.6.1.1=00aa00bb 1.2.3.4.value1=1234 1.2.3.4.value2=abcdef");
	}


}
