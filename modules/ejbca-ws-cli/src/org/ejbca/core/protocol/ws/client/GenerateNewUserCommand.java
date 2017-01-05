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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.cesecore.certificates.endentity.EndEntityConstants;
import org.cesecore.certificates.endentity.EndEntityType;
import org.cesecore.certificates.endentity.EndEntityTypes;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.AuthorizationDeniedException_Exception;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.ExtendedInformationWS;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserDoesntFullfillEndEntityProfile_Exception;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.ui.cli.ErrorAdminCommandException;
import org.ejbca.ui.cli.IAdminCommand;
import org.ejbca.ui.cli.IllegalAdminCommandException;

/**
 * Adds a user to the database.
 *
 * @version $Id$
 */
public class GenerateNewUserCommand extends EJBCAWSRABaseCommand implements IAdminCommand{

	
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
	private static final int ARG_PKCS10             = 14;
	private static final int ARG_ENCODING           = 15;
	private static final int ARG_HARDTOKENSN        = 16;
	private static final int ARG_OUTPUTPATH         = 17;

	private static final int NR_OF_MANDATORY_ARGS = ARG_HARDTOKENSN+1;
	private static final int MAX_NR_OF_ARGS = ARG_OUTPUTPATH+1;

    public GenerateNewUserCommand(String[] args) {
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
    		System.exit(-1); // NOPMD, it's not a JEE app
    	}

    	try {
            userdata.setUsername(myArgs[ARG_USERNAME]);
            userdata.setPassword(myArgs[ARG_PASSWORD]);
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

            if(!myArgs[ARG_ISSUERALIAS].equalsIgnoreCase("NONE")){
            	userdata.setEmail(myArgs[ARG_ISSUERALIAS]);
            }
            
            final String username = myArgs[ARG_USERNAME];
            final String password = myArgs[ARG_PASSWORD];
            final String pkcs10 = getPKCS10(myArgs[ARG_PKCS10]);
            final String encoding = getEncoding(myArgs[ARG_ENCODING]);
            final String hardtokensn = getHardTokenSN(myArgs[ARG_HARDTOKENSN]);
            final String outputPath = myArgs.length>ARG_OUTPUTPATH ? getOutputPath(myArgs[ARG_OUTPUTPATH]) : null;
            
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
            getPrintStream().println("Hard Token Issuer Alias: "+(userdata.getHardTokenIssuerName()!=null ? userdata.getHardTokenIssuerName() :"NONE"));
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
            	
             	CertificateResponse result = getEjbcaRAWS().pkcs10Request(username,password,pkcs10,hardtokensn,CertificateHelper.RESPONSETYPE_CERTIFICATE);
            	
            	if(result==null){
            		getPrintStream().println("No certificate could be generated for user, check server logs for error.");
            	}else{
            		String filepath = username;
            		if(encoding.equals("DER")){
            			filepath += ".cer";
            		}else{
            			filepath += ".pem";
            		}
            		if(outputPath != null){
            			filepath = outputPath + "/" + filepath;
            		}
            		
            		
            		if(encoding.equals("DER")){
            			FileOutputStream fos = new FileOutputStream(filepath);
            			fos.write(CertificateHelper.getCertificate(result.getData()).getEncoded());
            			fos.close();
            		}else{
            			FileOutputStream fos = new FileOutputStream(filepath);
            			ArrayList<java.security.cert.Certificate> list = new ArrayList<java.security.cert.Certificate>();
            			list.add(CertificateHelper.getCertificate(result.getData()));
            			fos.write(CertTools.getPemFromCertificateChain(list));
            			fos.close();            				            				
            		}
            		getPrintStream().println("Certificate generated, written to " + filepath);
            	}
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
		System.exit(-1); // NOPMD, it's not a JEE app
		return 0;
	}
	
	private String getHardTokenSN(String hardtokensn) {
		if(hardtokensn.equalsIgnoreCase("NONE")){
		  return null;
		}
		
		return hardtokensn;
	}
	
	private String getPKCS10(String pkcs10Path) {
		String retval=null;
		try {
			FileInputStream fis = new FileInputStream(pkcs10Path);
			byte[] contents = new byte[fis.available()];
			fis.read(contents);			
			fis.close();
			retval = new String(contents);
		} catch (FileNotFoundException e) {
			getPrintStream().println("Error : PKCS10 file could not found.");
			System.exit(-1); // NOPMD, it's not a JEE app		
		} catch (IOException e) {
			getPrintStream().println("Error reading content of PKCS10 file.");
			System.exit(-1); // NOPMD, it's not a JEE app	
		}
		
		
		return retval;
	}

	private String getOutputPath(String outputpath) {
		File dir = new File(outputpath);
		if(!dir.exists()){
			getPrintStream().println("Error : Output directory doesn't seem to exist.");
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		if(!dir.isDirectory()){
			getPrintStream().println("Error : Output directory doesn't seem to be a directory.");
			System.exit(-1); // NOPMD, it's not a JEE app			
		}
		if(!dir.canWrite()){
			getPrintStream().println("Error : Output directory isn't writeable.");
			System.exit(-1); // NOPMD, it's not a JEE app

		}
		return outputpath;
	}

	private String getEncoding(String encoding) {
		if(!encoding.equalsIgnoreCase("PEM") && !encoding.equalsIgnoreCase("DER")){
			usage();
			System.exit(-1); // NOPMD, it's not a JEE app
		}
		
		return encoding.toUpperCase();
	}


	protected void usage() {
		getPrintStream().println("Command used to add or edit userdata and to generate the user in one step.");
		getPrintStream().println("Usage : generatenewuser <username> <password> <clearpwd (true|false)> <subjectdn> <subjectaltname or NULL> <email or NULL> <caname> <type> <token> <status> <endentityprofilename> <certificateprofilename> <issueralias (or NONE)> <pkcs10path> <encoding (DER|PEM)> <hardtokensn (or NONE)> <outputpath (optional)>\n\n");
        getPrintStream().println("DN is of form \"C=SE, O=MyOrg, OU=MyOrgUnit, CN=MyName\" etc.");
        getPrintStream().println(
            "SubjectAltName is of form \"rfc822Name=<email>, dNSName=<host name>, uri=<http://host.com/>, ipaddress=<address>, guid=<globally unique id>\"");

        getPrintStream().println("Type (mask): INVALID=0; END-USER=1; KEYRECOVERABLE=128; SENDNOTIFICATION=256");
		
        getPrintStream().println("Existing tokens : " + "USERGENERATED" + ", " +
        		"P12" + ", "+ "JKS" + ", "  + "PEM");
        getPrintStream().println("Existing statuses (new users will always be set as NEW) : NEW, INPROCESS, FAILED, HISTORICAL");
        getPrintStream().println("outputpath : directory where certificate is written in form username+.cer|.pem ");
        getPrintStream().println();
        ParseUserData.printCliHelp(getPrintStream());
	}


}
