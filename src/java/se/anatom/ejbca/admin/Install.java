/*
 * Created on 2004-jan-24
 *
 * Class used as an install script of ejbca
 */
package se.anatom.ejbca.admin;

import java.io.FileInputStream;
import java.util.Properties;
import java.util.regex.Pattern;

import org.ietf.ldap.LDAPDN;

/**
 * @author philip
 *
 * The main porpose of this program is to provide easy installment of EJBCA.
 */
public class Install {

	public static int ARG_LANGUAGE   =  0;
	public static int ARG_VERSION      =  1;
	public static int ARG_APPSERVER  =  2;
	public static int ARG_WEBSERVER =  3;
	
	private final static int APPSERVER_JBOSS         = 0; 
	private final static int APPSERVER_WEBLOGIC  = 1;
	
    private final static int WEBSERVER_JETTY      = 0;
    private final static int WEBSERVER_TOMCAT  = 1;

    private int appserver = APPSERVER_JBOSS;
    private int webserver = WEBSERVER_JETTY;

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
	private Pattern nondigitordot = Pattern.compile("[^0-9 \\.]");
	private Pattern nonword = Pattern.compile("\\W");
	private Properties text; 
	
	public Install(String language, String version, String appserverstring, String webserverstring) throws Exception{
		text = new Properties();
		text.load(new FileInputStream("install." + language.toLowerCase() + ".properties"));
		if(version.equalsIgnoreCase("primeca")){
			text.load(new FileInputStream("installprimeca." + language.toLowerCase() + ".properties"));
		}
   
        if(appserverstring.equalsIgnoreCase("weblogic")){
            this.appserver = APPSERVER_WEBLOGIC;
        }

        if(appserverstring.equalsIgnoreCase("tomcat")){
            this.webserver = WEBSERVER_TOMCAT;
        }
	}			
	
	public void run(){
		
	   System.out.println(text.getProperty("WELCOME"));
	   System.out.println(text.getProperty("NEXT"));
	   
	   
	}
					
	public static void main(String[] args) throws Exception {
		if(args.length != 4){
			System.out.println("Usage: install <language> <ejbca|primeca> <jboss|weblogic> <jetty|tomcat>");
			System.exit(-1);
		}
		Install install = new Install(args[ARG_LANGUAGE], args[ARG_VERSION], args[ARG_APPSERVER], args[ARG_WEBSERVER]);
		install.run();
	}
	
	private void displayWelcomeScreen(){
		
		
	}
	
	private void getCAName(){
		
	}
	
	private void getCADN(){
		
	}
	
	private void getKeySize(){
		
	}
	
	private void getValidity(){
		
	}
	
	private void getPolicyId(){
		
	}
	
	private void displayCAIsBeingGenerated(){
		
	}
	
	private void getComputerName(){
		
	}
	
	private void getSSLServerCertDN(){
		
	}
	
	private void getSSLKeyStorePasswd(){
		
	}
	
	private void getSuperAdminPasswd(){
		
	}
	
	private void getJavaCACertsPasswd(){
		
	}
	
	private void displayAdminWebGenerating(){
		
	}
	
	private void displayEndMessage(){
		
	}
	
	private boolean answerInBoolean(String answer){
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
	
	private int getDigitAnser(String answer){
		return Integer.parseInt(answer);
	}
	
	private boolean answerLegalDN(String answer){
		return LDAPDN.isValid(answer);
	}
	
	private boolean answerLegalName(String answer){
		 return !nonword.matcher(answer).find();
	}
	
}
