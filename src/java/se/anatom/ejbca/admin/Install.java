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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Properties;
import java.util.regex.Pattern;

import org.ietf.ldap.LDAPDN;

import se.anatom.ejbca.util.passgen.PasswordGeneratorFactory;

/** Class used as an install script of ejbca
 * 
 * @author philip
 * @version $Id: Install.java,v 1.13 2004-05-08 10:13:28 anatom Exp $
 *
 * The main porpose of this program is to provide easy installment of EJBCA.
 */
public class Install extends BaseCommand {

	public static int ARG_COMMAND   =  0;
	public static int ARG_OS               =  1;
	public static int ARG_LANGUAGE   =  2;
	public static int ARG_VERSION      =  3;
	public static int ARG_APPSERVER  =  4;
	public static int ARG_WEBSERVER =  5;
	
	private final static int OS_UNIX          = 0; 
	private final static int OS_WINDOWS  = 1;
		
	private final static int APPSERVER_JBOSS         = 0; 
	private final static int APPSERVER_WEBLOGIC  = 1;
	
    private int appserver = APPSERVER_JBOSS;

    private int os = OS_UNIX;
    
	private String caname = "";
	private String cadn = "";
	private int keysize = 0;
	private int validity = 0;
	private String policyid = "";

	private String computername = "";
	private String servercertdn = "";
	private String serverkeystorepasswd = "";
	private String superadminpasswd = "";
	private String javacacertspasswd = "";
			
	private Pattern nondigit = Pattern.compile("\\D");
	private Pattern nondigitordot = Pattern.compile("[^0-9\\.]");
	private Pattern notcomputername = Pattern.compile("[^0-9a-zA-z\\-\\.]");
	private Pattern nonword = Pattern.compile("\\W");
	private Properties text; 
	
	private BufferedReader reader = null;
	
	public Install(String osstring, String language, String version, String appserverstring) throws Exception{
			
        super();
		reader = new BufferedReader(new InputStreamReader(System.in));
		
		text = new Properties();
		text.load(this.getClass().getResourceAsStream("/" + "install." + language.toLowerCase() + ".properties"));
						   
		if(osstring.equalsIgnoreCase("unix")){
			this.os = OS_UNIX;
		}
		if(osstring.equalsIgnoreCase("windows")){
			this.os = OS_WINDOWS;
		}		
        if(appserverstring.equalsIgnoreCase("weblogic")){
            this.appserver = APPSERVER_WEBLOGIC;
        }
	}			
	
	public void run(){
		if(checkRequirements()){;
		  displayWelcomeScreen();
	      while(!collectData());
	      runInstall();	
		}else{
	      System.exit(-1);	
		}
	}
					
	public static void main(String[] args) throws Exception {
		if(args.length != 5){
			System.out.println("Usage: install install <unix|windows> <language> <ejbca|primeca> <jboss|weblogic>\n" +
					                     " Or : install displayendmessage <unix|windows> <language> <ejbca|primeca> <jboss|weblogic>");
			System.exit(-1);
		}
		
		Install install = new Install(args[ARG_OS], args[ARG_LANGUAGE], args[ARG_VERSION], args[ARG_APPSERVER]);
		
		if(args.length == 5){
			if(args[Install.ARG_COMMAND].equalsIgnoreCase("install")){
		      install.run();
		    }else{		    			
			  if(args[Install.ARG_COMMAND].equalsIgnoreCase("displayendmessage")){		
			  	install.displayEndMessage();    
			  }else{
				System.out.println("Usage: install install <unix|windows> <language> <ejbca> <jboss|weblogic>\n" +
				" Or : install displayendmessage <unix|windows><language> <ejbca> <jboss|weblogic>");
				System.exit(-1);
			  }
		    }
		}					   			
		
	}
	
	
	/**
	 * Method checking if all reuirements are meet before starting the installation.
	 * If requirements aren't meet then will a error message be  displayed.
	 * 
	 * @return true if all requirements are set.
	 */
	private boolean checkRequirements(){
	  boolean retval = appServerRunning();
      if (!retval) {
        System.out.println(text.getProperty("APPSERVMUSTBERUNNING"));
        //return false;
      }
      try {
          retval = strongCryptoInstalled();          
          System.out.println(text.getProperty("STRONGCRYPTOMUSTBEINSTALLED"));
          return false;
      } catch (Exception e) {
          System.out.println(text.getProperty("STRONGCRYPTOMUSTBEINSTALLED"));
          return false;
      }
	  //return retval;
	}
	
	private void displayWelcomeScreen(){
		System.out.print(text.getProperty("WELCOMETO"));
		System.out.print(text.getProperty("THISSCRIPT"));
		System.out.print(text.getProperty("THEAPPLICATIONISDEPLOYED"));
		System.out.print(text.getProperty("YOUSHOULDPERFORM"));
		System.out.print(text.getProperty("ISTHESEREQUIREMENTSMEET"));
		String answer = getAnswer();
		while(!answerInBoolean(answer)){
			System.out.print(text.getProperty("PLEASETYPEEITHERYESORNO"));
			answer = getAnswer();
		}
		boolean cont = getBooleanAnswer(answer);
		if(!cont)
		  System.exit(-1);	 
		
	}
	
	private boolean collectData(){
	    
	    System.out.print(text.getProperty("THISINSTALLATIONWILL"));
	    getCAName();
	    getCADN();
	    getKeySize();
	    getValidity();
	    getPolicyId();
	    
	    System.out.print(text.getProperty("NOWSOMEADMINWEB"));
	    
	    getComputerName();
	    getSSLServerCertDN();
	    getSSLKeyStorePasswd();
	    getSuperAdminPasswd();    
	  //  getJavaCACertsPasswd();
	     	    	   
		return isDataCorrect();
	}
	
	private void getCAName(){
		System.out.print(text.getProperty("ENTERSHORTNAME"));
		String answer = getAnswer();
		while(!answerLegalName(answer)){
			System.out.print(text.getProperty("ILLEGALCANAME"));
			System.out.print(text.getProperty("ENTERSHORTNAME"));
			answer = getAnswer();
		}
		this.caname = answer;
	   	
	}
	
	private void getCADN(){
		System.out.print(text.getProperty("ENTERDN"));
		String answer = getAnswer();
		while(!answerLegalDN(answer)){
			System.out.print(text.getProperty("ILLEGALDN"));
			System.out.print(text.getProperty("ENTERDN"));
			answer = getAnswer();
		}
		this.cadn = answer;				
	}
	
	private void getKeySize(){
		System.out.print(text.getProperty("ENTERKEYSIZE"));
		String answer = getAnswer();
		while(!answerLegalKeySize(answer)){
			System.out.print(text.getProperty("ILLEGALKEYSIZE"));
			System.out.print(text.getProperty("ENTERKEYSIZE"));
			answer = getAnswer();
		}
		this.keysize = this.getDigitAnswer(answer);		
	}
	
	private void getValidity(){
		System.out.print(text.getProperty("ENTERVALIDITY"));
		String answer = getAnswer();
		while(!answerLegalValidity(answer)){
			System.out.print(text.getProperty("ILLEGALVALIDITY"));
			System.out.print(text.getProperty("ENTERVALIDITY"));
			answer = getAnswer();
		}
		this.validity = this.getDigitAnswer(answer);				
	}
	
	private void getPolicyId(){
		System.out.print(text.getProperty("ENTERPOLICYID"));
		String answer = getAnswer();
		while(!answerLegalPolicyId(answer)){
			System.out.print(text.getProperty("ILLEGALPOLICYID"));
			System.out.print(text.getProperty("ENTERPOLICYID"));
			answer = getAnswer();
		}
		
		this.policyid = this.getPolicyId(answer);					
	}
	
	
	
	private void getComputerName(){
		System.out.print(text.getProperty("ENTERCOMPUTERNAME"));
		String answer = getAnswer();
		while(!answerLegalComputerName(answer)){
			System.out.print(text.getProperty("ILLEGALCOMPUTERNAME"));
			System.out.print(text.getProperty("ENTERCOMPUTERNAME"));
			answer = getAnswer();
		}
		
		this.computername = answer;											
	}
	
	private void getSSLServerCertDN(){
		System.out.print(text.getProperty("ENTERSERVERDN"));
		String answer = getAnswer();
		while(!answerLegalDN(answer)){
			System.out.print(text.getProperty("ILLEGALSERVERDN"));
			System.out.print(text.getProperty("ENTERSERVERDN"));
			answer = getAnswer();
		}
		this.servercertdn = answer;						
	}
	
	private void getSSLKeyStorePasswd(){
		
		this.serverkeystorepasswd = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_LETTERSANDDIGITS).getNewPassword(8,8);
				
/*		System.out.print(text.getProperty("ENTERADMINWEBPASSWORD"));
		String answer = getAnswer();
		while(!answerLegalPassword(answer)){
			System.out.print(text.getProperty("ILLEGALADMINWEBPASSWORD"));
			System.out.print(text.getProperty("ENTERADMINWEBPASSWORD"));
			answer = getAnswer();
		}
		this.serverkeystorepasswd = answer;*/										
	}
	
	private void getSuperAdminPasswd(){
		System.out.print(text.getProperty("ENTERSUPERADMINPASSWORD"));
		String answer = getAnswer();
		while(!answerLegalPassword(answer)){
			System.out.print(text.getProperty("ILLEGALSUPERADMINPASSWORD"));
			System.out.print(text.getProperty("ENTERSUPERADMINPASSWORD"));
			answer = getAnswer();
		}
		this.superadminpasswd = answer;												
	}
	
	private void getJavaCACertsPasswd(){
		System.out.print(text.getProperty("ENTERCACERTSPASSWORD"));
		String answer = getAnswer();
		while(!answerLegalPassword(answer)){
			System.out.print(text.getProperty("ILLEGALCACERTSPASSWORD"));
			System.out.print(text.getProperty("ENTERCACERTSPASSWORD"));
			answer = getAnswer();
		}
		this.javacacertspasswd = answer;		
	}
	
	private boolean isDataCorrect(){
		System.out.print(text.getProperty("YOUHAVEENTEREDTHEFOLLOWING"));
		
		System.out.println(text.getProperty("CANAME") + " " + this.caname);
		System.out.println(text.getProperty("CADN") + " " + this.cadn);
		System.out.println(text.getProperty("KEYSIZE") + " " + this.keysize);
		System.out.println(text.getProperty("VALIDITY") + " " + this.validity);
		System.out.print(text.getProperty("POLICYID") + " ");
		if(this.policyid.equalsIgnoreCase("null"))
			System.out.println(text.getProperty("NOPOLICYID"));
		else
			System.out.println(this.policyid);
		System.out.println(text.getProperty("COMPUTERNAME") + " " + this.computername);
		System.out.println(text.getProperty("SERVERDN") + " " + this.servercertdn);		
		System.out.println(text.getProperty("SUPERADMINPASSWORD") + " " + this.superadminpasswd);		
																																			
		 boolean correct = false;
		 System.out.print(text.getProperty("ISTHISCORRECT"));
         String answer = getAnswer();
         while(!this.answerInBoolean(answer) && !answer.equalsIgnoreCase("e") && !answer.equalsIgnoreCase("exit")){
         	System.out.print(text.getProperty("PLEASETYPEEITHERYESNOEXIT"));
         	answer = getAnswer();
         }         
         if(answer.equalsIgnoreCase("e") || answer.equalsIgnoreCase("Exit"))
         	System.exit(0);
		 
		return getBooleanAnswer(answer);
	}
	
	
	private void runInstall(){
		displayInstallingMessage();
        
		if(this.os == OS_WINDOWS){
			try {
				String[] command = new String[7];
				command[0] = "ca.cmd";
				command[1] = "init";
				command[2] = this.caname;
				command[3] = "\"" + this.cadn + "\"";
				command[4] = Integer.toString(this.keysize);
				command[5] = Integer.toString(this.validity);
				command[6] = this.policyid.trim();
				Process runcainit = Runtime.getRuntime().exec(command);
				
				BufferedReader br = new BufferedReader(new InputStreamReader(runcainit.getInputStream()));
				Thread.sleep(1000);
				String line = "";
				while((line = br.readLine()) != null){
					System.out.println(line);
				}
				if(runcainit.waitFor() != 0){					
					System.out.println(text.getProperty("ERRORINITCA"));
					System.exit(-1);
				}				
			} catch (Exception e) {				
		    	System.out.println(text.getProperty("ERRORINITCA") + e);
				System.exit(-1);
			} 	
			System.out.print(text.getProperty("SETUPOFADMINWEB"));
			try {	
				String[] command = new String[7];
				command[0] = "setup-adminweb.cmd";
				command[1] = this.caname;
				command[2] = "\"" + this.servercertdn + "\"";
				command[3] = this.serverkeystorepasswd;
				command[4] = this.superadminpasswd;
				command[5] = "dummy";
				command[6] = this.computername;
				Process setupadminweb = Runtime.getRuntime().exec(command);											   			   			  
				
				BufferedReader br = new BufferedReader(new InputStreamReader(setupadminweb.getInputStream()));
				Thread.sleep(1000);
				String line = "";
				while((line = br.readLine()) != null);
				if(setupadminweb.waitFor() != 0){
					System.out.println(text.getProperty("ERRORSETTINGUPADMINWEB"));
					System.exit(-1);
				}
				command = new String[5];
				command[0] = "ca.cmd";
				command[1] = "getrootcert";
				command[2] = this.caname;
				command[3] = "tmp\\rootca.der";
				command[4] = "-der";
				Process getrootcert = Runtime.getRuntime().exec(command);
				
				if(getrootcert.waitFor() != 0){
					System.out.println(text.getProperty("ERRORSETTINGUPADMINWEB"));
					System.exit(-1);
				}				
			} catch (Exception e) {		
				System.out.println(text.getProperty("ERRORSETTINGUPADMINWEB") + e);
				System.exit(-1);
			}
		}
		if(os == OS_UNIX){			
			try {
				String[] command = new String[7];
				command[0] = "./ca.sh";
			    command[1] = "init";
				command[2] = this.caname;
				command[3] = this.cadn;
				command[4] = Integer.toString(this.keysize);
				command[5] = Integer.toString(this.validity);
				command[6] = this.policyid.trim();
				Process runcainit = Runtime.getRuntime().exec(command);
			    								
				BufferedReader br = new BufferedReader(new InputStreamReader(runcainit.getInputStream()));
				Thread.sleep(1000);
				String line = "";
				while((line = br.readLine()) != null){
					System.out.println(line);
				}	
				if(runcainit.waitFor() != 0){
					System.out.println(text.getProperty("ERRORINITCA"));
					System.exit(-1);
				}				
			} catch (Exception e) {
				System.out.println(text.getProperty("ERRORINITCA") + e);
				System.exit(-1);
			} 
			System.out.print(text.getProperty("SETUPOFADMINWEB"));
			try {			  
				
				String[] command = new String[7];
				command[0] = "./setup-adminweb.sh";
				command[1] = this.caname;
				command[2] = this.servercertdn;
				command[3] = this.serverkeystorepasswd;
				command[4] = this.superadminpasswd;
				command[5] = "changeit";
				command[6] = this.computername;
				Process setupadminweb = Runtime.getRuntime().exec(command);											   			   			  
								
				if(setupadminweb.waitFor() != 0){
					System.out.print(text.getProperty("ERRORSETTINGUPADMINWEB"));
					System.exit(-1);
				}

				command = new String[5];
				command[0] = "./ca.sh";
				command[1] = "getrootcert";
				command[2] = this.caname;
				command[3] = "tmp/rootca.der";
				command[4] = "-der";
				Process getrootcert = Runtime.getRuntime().exec(command);											   			   
											
				if(getrootcert.waitFor() != 0){
					System.out.println(text.getProperty("ERRORSETTINGUPADMINWEB"));
					System.exit(-1);
				}
								
			} catch (Exception e) {
				System.out.println(text.getProperty("ERRORSETTINGUPADMINWEB") + e);
				System.exit(-1);
			}
	    }	
		
	}
	
	private void displayInstallingMessage(){
		System.out.print(text.getProperty("THEINSTALLATIONWILLNOWSTART"));		
	}
	
	public void displayEndMessage(){
		System.out.print(text.getProperty("INSTALLATIONCOMPLETE"));
		System.out.print(text.getProperty("REMAININGSTEPS"));
		System.out.print(text.getProperty("GOTOURL"));
		System.out.print(text.getProperty("ANDYOUAREALLSET"));
		System.out.print(text.getProperty("INTERESTEDINSUPPORT"));		
	}
	
	
	private String getAnswer(){
		String returnval = "";			
		try {
			returnval=  reader.readLine();
		} catch (Exception e) {}
		
		return returnval;
	}
	
	private boolean answerInBoolean(String answer) {		
		return answer.equalsIgnoreCase("y") || answer.equalsIgnoreCase("n") 
		           || answer.equalsIgnoreCase("yes") || answer.equalsIgnoreCase("no");
	}
	
	private boolean getBooleanAnswer(String answer){								
		return answer.equalsIgnoreCase("y") || answer.equalsIgnoreCase("yes"); 
	}
	
	private boolean answerInDigits(String answer){
		return ! nondigit.matcher(answer).find();
	}
	
	private boolean answerInDigitsAndDots(String answer){
	    return !nondigitordot.matcher(answer).find();
    }
	
	private int getDigitAnswer(String answer){
		return Integer.parseInt(answer);
	}
	
	private boolean answerLegalDN(String answer){
		return !answer.trim().equals("") && LDAPDN.isValid(answer);
	}
	
	private boolean answerLegalName(String answer){
		 return !answer.trim().equals("") && !nonword.matcher(answer).find();
	}
	
	private boolean answerLegalPolicyId(String answer){
		if(answer.equalsIgnoreCase("NO"))
			return true;
		
		return !answer.trim().equals("") && !nondigitordot.matcher(answer).find();
	}
	
	private String getPolicyId(String answer){
		if(answer.equalsIgnoreCase("NO"))
			return "null";
		
		return answer;		
	}
	
	private boolean answerLegalKeySize(String answer){		
		if(!answerInDigits(answer))
			return false;
		
		int keysize = getInt(answer);
		
		return keysize == 512 || keysize == 1024 || keysize == 2048 || keysize == 4096;
	}
	
	private boolean answerLegalValidity(String answer){
		if(!answerInDigits(answer))
			return false;
				
		  int val = getInt(answer);
		
		return val > 0 && val < 35600;		
	}
	
	private int getInt(String answer){
		int returnval = -1;
		try{
			returnval = Integer.parseInt(answer);			
		}catch(Exception e){}
		return returnval;
	}
	
	private boolean answerLegalComputerName(String answer){
		return !answer.trim().equals("") && !this.notcomputername.matcher(answer).find();
	}
	
	private boolean answerLegalPassword(String answer){
		int len = answer.length();
		
		if(answer.indexOf(' ') != -1 || answer.indexOf('"') != -1 || answer.indexOf('\'') != -1)
			return false;
		
		return len > 1 && len < 14;
	    			
	}
	
	
}
