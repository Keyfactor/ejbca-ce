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

package se.anatom.ejbca.ca.caadmin.hardcatokens;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Iterator;
import java.util.Properties;

import org.apache.log4j.Logger;

import se.anatom.ejbca.SecConst;
import se.anatom.ejbca.ca.caadmin.IHardCAToken;
import se.anatom.ejbca.ca.exception.CATokenAuthenticationFailedException;
import se.anatom.ejbca.ca.exception.CATokenOfflineException;
import se.anatom.ejbca.util.Base64;

/**
 * @author herrvendil
 * 
 * Class used as test and demonstrationclass when writing HardCAToken plug-ins as HSMs.
 * 
 * Observe: Remember to add a loadClass("thisclass") row to the HardCATokenManager.init() method when adding new plug-ins.
 * 
 * 
 */
public class HardCATokenSample implements IHardCAToken {
    /** Log4j instance for Base */
    private static transient Logger baseLog = Logger.getLogger(HardCATokenSample.class);
	private transient Logger log;		
	
	// TODO set this right after testing.
	private static boolean registered = HardCATokenManager.register("se.anatom.ejbca.ca.caadmin.hardcatokens.HardCATokenSample", "HardCATokenSample", false, true);
	
	private static byte[] signkeypairenc = Base64.decode(
			("rO0ABXNyABVqYXZhLnNlY3VyaXR5LktleVBhaXKXAww60s0SkwIAAkwACnByaXZh"
			+"dGVLZXl0ABpMamF2YS9zZWN1cml0eS9Qcml2YXRlS2V5O0wACXB1YmxpY0tleXQA"
			+"GUxqYXZhL3NlY3VyaXR5L1B1YmxpY0tleTt4cHNyADFvcmcuYm91bmN5Y2FzdGxl"
			+"LmpjZS5wcm92aWRlci5KQ0VSU0FQcml2YXRlQ3J0S2V5bLqHzgJzVS4CAAZMAA5j"
			+"cnRDb2VmZmljaWVudHQAFkxqYXZhL21hdGgvQmlnSW50ZWdlcjtMAA5wcmltZUV4"
			+"cG9uZW50UHEAfgAFTAAOcHJpbWVFeHBvbmVudFFxAH4ABUwABnByaW1lUHEAfgAF"
			+"TAAGcHJpbWVRcQB+AAVMAA5wdWJsaWNFeHBvbmVudHEAfgAFeHIALm9yZy5ib3Vu"
			+"Y3ljYXN0bGUuamNlLnByb3ZpZGVyLkpDRVJTQVByaXZhdGVLZXmyNYtAHTGFVgMA"
			+"BEwAB21vZHVsdXNxAH4ABUwAEHBrY3MxMkF0dHJpYnV0ZXN0ABVMamF2YS91dGls"
			+"L0hhc2h0YWJsZTtMAA5wa2NzMTJPcmRlcmluZ3QAEkxqYXZhL3V0aWwvVmVjdG9y"
			+"O0wAD3ByaXZhdGVFeHBvbmVudHEAfgAFeHBzcgAUamF2YS5tYXRoLkJpZ0ludGVn"
			+"ZXKM/J8fqTv7HQMABkkACGJpdENvdW50SQAJYml0TGVuZ3RoSQATZmlyc3ROb256"
			+"ZXJvQnl0ZU51bUkADGxvd2VzdFNldEJpdEkABnNpZ251bVsACW1hZ25pdHVkZXQA"
			+"AltCeHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw///////////////+"
            +"/////gAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAAgI/DALgijbOgTrfu92VQ4Eax"
			+"KsFSxOESv1vCxLVXvoRxED/LYfIv4ylbyhNdheuYUtQsTlqNzxUrd3AvbovI9TKl"
			+"kNYs7ICrEJ5Ir2EJrlVTuXnHjLRXwlWYw2J5WGPU15B9tUjcv0HLSJXgax52xEac"
			+"2VuwVvozPlbKXBXghPeReHNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgD"
			+"AAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAACHcIAAAACwAAAAB4"
			+"c3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVt"
			+"ZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9P"
			+"YmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwC"
			+"AAB4cAAAAApwcHBwcHBwcHBweHNxAH4ACv///////////////v////4AAAABdXEA"
			+"fgAOAAAAgA88mbzqXJ5nJTC1cR8Z3Utgx6lJvngkZoexMuwNarHa0eARDEaA8NCX"
			+"W+mFhgYcVNsL/xn14bbaroQDYvIJ0ILu/4fciaFrngqLYbZTrYAQCOtC+akP4cru"
			+"uCJwJJ7duocUl4fGktHhq/knmujeOePBjpeevWme7VD4yZz97qABeHhzcQB+AAr/"
            +"//////////////7////+AAAAAXVxAH4ADgAAAEA7cNGRFsoYtTo8DVK9VZnao9IA"
			+"1H3cYAc/hYehyey+uNRh6Xh27OcjeFemBmGrvy8NONMizV3nbk/Cerl8TPQ5eHNx"
			+"AH4ACv///////////////v////4AAAABdXEAfgAOAAAAQAUitZLEEBHZp9pDInbI"
			+"fzOhht9LWetuIr5Npi9vE/6PYnoz5AWtDzp/1XJbzUGrrR2ybpEweEG6q4V0IJe/"
			+"pgF4c3EAfgAK///////////////+/////gAAAAF1cQB+AA4AAABAtUkn0jjn/2qV"
			+"7brM7c/eOBmNg4uhEZn+xM6tq6WAnconFeX4EPO1ap5WYT0hbdzRFD2wz8OxuHz9"
			+"I3hX/4IFQXhzcQB+AAr///////////////7////+AAAAAXVxAH4ADgAAAEDE0zGf"
			+"1U8IV68lRnim6wnmW/7s3vJYCU7P2ljJ/rd8w1/AR5gJvkOaDvZykEKwy2uyFZjx"
			+"yIZ3mvwgSMPMiWUBeHNxAH4ACv///////////////v////4AAAABdXEAfgAOAAAA"
			+"QLr7v/gjbnmvWH5JXrcYXgUG9/JOX69Fo1RCaD8fVIpyN2gMTeZLWd8KyRd2ci02"
			+"xgDdhDAbmKZf6XCPFyAowpF4c3EAfgAK///////////////+/////gAAAAF1cQB+"
			+"AA4AAAADAQABeHNyAC1vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VS"
			+"U0FQdWJsaWNLZXklImoOW/pshAIAAkwAB21vZHVsdXNxAH4ABUwADnB1YmxpY0V4"
			+"cG9uZW50cQB+AAV4cHEAfgANcQB+ACM=").getBytes());
																														
	
	private static PrivateKey privatesignkey = null;
	
	
	private static PublicKey publicsignkey = null;
	
	private static byte[] enckeypairenc = Base64.decode(
			("rO0ABXNyABVqYXZhLnNlY3VyaXR5LktleVBhaXKXAww60s0SkwIAAkwACnByaXZh"
			+"dGVLZXl0ABpMamF2YS9zZWN1cml0eS9Qcml2YXRlS2V5O0wACXB1YmxpY0tleXQA"
			+"GUxqYXZhL3NlY3VyaXR5L1B1YmxpY0tleTt4cHNyADFvcmcuYm91bmN5Y2FzdGxl"
			+"LmpjZS5wcm92aWRlci5KQ0VSU0FQcml2YXRlQ3J0S2V5bLqHzgJzVS4CAAZMAA5j"
			+"cnRDb2VmZmljaWVudHQAFkxqYXZhL21hdGgvQmlnSW50ZWdlcjtMAA5wcmltZUV4"
			+"cG9uZW50UHEAfgAFTAAOcHJpbWVFeHBvbmVudFFxAH4ABUwABnByaW1lUHEAfgAF"
			+"TAAGcHJpbWVRcQB+AAVMAA5wdWJsaWNFeHBvbmVudHEAfgAFeHIALm9yZy5ib3Vu"
			+"Y3ljYXN0bGUuamNlLnByb3ZpZGVyLkpDRVJTQVByaXZhdGVLZXmyNYtAHTGFVgMA"
			+"BEwAB21vZHVsdXNxAH4ABUwAEHBrY3MxMkF0dHJpYnV0ZXN0ABVMamF2YS91dGls"
			+"L0hhc2h0YWJsZTtMAA5wa2NzMTJPcmRlcmluZ3QAEkxqYXZhL3V0aWwvVmVjdG9y"
			+"O0wAD3ByaXZhdGVFeHBvbmVudHEAfgAFeHBzcgAUamF2YS5tYXRoLkJpZ0ludGVn"
			+"ZXKM/J8fqTv7HQMABkkACGJpdENvdW50SQAJYml0TGVuZ3RoSQATZmlyc3ROb256"
			+"ZXJvQnl0ZU51bUkADGxvd2VzdFNldEJpdEkABnNpZ251bVsACW1hZ25pdHVkZXQA"
			+"AltCeHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhw///////////////+"
            +"/////gAAAAF1cgACW0Ks8xf4BghU4AIAAHhwAAAAgJiNTc1TY9naOkLIbRGcBW7E"
			+"h+AiT3sn7QaTXgleT7EP68wmxPYIXeodi8M4iv+8koLW3NT/XG6mwTy5GFWQqJ8k"
			+"FVgM+KFsP40PCXZq02fB0dBnivo1k6ccAhTWngMpd4qSYVgK42Klqku2PK+9vEUw"
			+"OeLim3FkKMYnphxpfXe3eHNyABNqYXZhLnV0aWwuSGFzaHRhYmxlE7sPJSFK5LgD"
			+"AAJGAApsb2FkRmFjdG9ySQAJdGhyZXNob2xkeHA/QAAAAAAACHcIAAAACwAAAAB4"
			+"c3IAEGphdmEudXRpbC5WZWN0b3LZl31bgDuvAQMAA0kAEWNhcGFjaXR5SW5jcmVt"
			+"ZW50SQAMZWxlbWVudENvdW50WwALZWxlbWVudERhdGF0ABNbTGphdmEvbGFuZy9P"
			+"YmplY3Q7eHAAAAAAAAAAAHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwC"
			+"AAB4cAAAAApwcHBwcHBwcHBweHNxAH4ACv///////////////v////4AAAABdXEA"
			+"fgAOAAAAgBPEW4x7fbjA2kPFDLz3ZozP0ntsdrgSmFf9yHWWTuU2lutBKsxmkSTA"
			+"51dIgFpa6PEjPkIrRKLh4LApm8makP66l+Qt73CLxzEmqRl7ZxEbXrPV8bALo2K4"
			+"bDHG/83+jCGoeYAHLbC4tQmqjMba3Wt0lYNqpHeZlwtR3uqiWoyheHhzcQB+AAr/"
            +"//////////////7////+AAAAAXVxAH4ADgAAAEDMH9eiaoYotp7mu/bmXffgd1P9"
			+"epIRq1wK1e85U/NViVYdgfdxeQf0U/mK+yfq9VAGmCn2c46gxq0hNykCmSc1eHNx"
			+"AH4ACv///////////////v////4AAAABdXEAfgAOAAAAQIKMrS3zZ2QwfcJcUHql"
			+"bsKET8O7PsLyxgYQp7ucZHDktP4CnUgxXwcM9WgN/ciZe+r5gokcZTDWz1Z8q/3s"
			+"Yml4c3EAfgAK///////////////+/////gAAAAF1cQB+AA4AAABAohOic8dgmTfa"
			+"7vniO1dPmzA+AdSMILeM3Av/UVhIS6dIh9SJlHtFzSS0Lfx7VRxfrUmbFK0gwvwy"
			+"vFlUpU8G2XhzcQB+AAr///////////////7////+AAAAAXVxAH4ADgAAAEDX76op"
			+"lk5Hj9lAiJRJl0MuhsraA/hj3zxdVz+x36tRF/uShXR8Mts9Q37CcrVkO2tSNPBR"
			+"CmQuIceQiK4nuZo9eHNxAH4ACv///////////////v////4AAAABdXEAfgAOAAAA"
			+"QLTbEx+wBtZQiJTqwHjDLoKof5B+/ROPkVZlEZSZDX6YOhcJVX0nL8qf4spa4K0P"
			+"T7zzOL5taWVWT7c+Vb1y3QN4c3EAfgAK///////////////+/////gAAAAF1cQB+"
			+"AA4AAAADAQABeHNyAC1vcmcuYm91bmN5Y2FzdGxlLmpjZS5wcm92aWRlci5KQ0VS"
			+"U0FQdWJsaWNLZXklImoOW/pshAIAAkwAB21vZHVsdXNxAH4ABUwADnB1YmxpY0V4"
			+"cG9uZW50cQB+AAV4cHEAfgANcQB+ACM=").getBytes());			
			
			
    private static PrivateKey privateenckey = null;
	
	   
	private static PublicKey publicenckey = null;
   
   
    private boolean authenticated = false;
    
    private boolean offline = false;
   
	public HardCATokenSample(){
		log = Logger.getLogger(this.getClass());
	}
	
	/**
	 * This method should initalize this plug-in with the properties configured in the adminweb-GUI.
     * 
     * The following properties is available:
     * OFFLINE = TRUE | FALSE (Default) 
     *
	 * 
	 */
	public void init(Properties properties, String signaturealgorithm) {
		log.debug("Init()");
          // Implement this.	  
		
		log.info("TestHardCAToken : init : Found the following properties :");
		Iterator iter = properties.keySet().iterator();
		while(iter.hasNext()){
		  Object key = iter.next();	
		  log.info(key + " : " + properties.get(key));	
		}
		
		if(properties.getProperty("OFFLINE", "FALSE").equals("TRUE"))
		  offline = true;
		
		log.info("TestHardCAToken : init : End of properties");
		
		try{
          ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(signkeypairenc));
		  KeyPair signkeys = (KeyPair) ois.readObject();
		  privatesignkey = signkeys.getPrivate();
		  publicsignkey = signkeys.getPublic();
          
          ois = new ObjectInputStream(new ByteArrayInputStream(enckeypairenc));
		  KeyPair enckeys = (KeyPair) ois.readObject();
		  privateenckey = enckeys.getPrivate();
		  publicenckey = enckeys.getPublic();
		  		 		  		 
		}catch(Exception e){
			e.printStackTrace();
		}				
	}
	

	/**
	 * Should return a reference to the private key.
	 */
	public PrivateKey getPrivateKey(int purpose) throws CATokenOfflineException {
		log.debug("getPrivateSignKey()");
		
		if(offline || !authenticated)
	      throw new CATokenOfflineException();
		
		
		if(purpose == SecConst.CAKEYPURPOSE_KEYENCRYPT)
		  return HardCATokenSample.privateenckey;
		  
		return HardCATokenSample.privatesignkey;
	}
	
	/**
	 * Should return a reference to the public key.
	 */
	public PublicKey getPublicKey(int purpose) throws CATokenOfflineException {
		log.debug("getPublicSignKey()");
		if(offline || !authenticated)
	      throw new CATokenOfflineException();

        if(purpose == SecConst.CAKEYPURPOSE_KEYENCRYPT) 
		  return HardCATokenSample.publicenckey;	 
			 
		return HardCATokenSample.publicsignkey;
	}
		
	
    /** Should return the signature Provider that should be used to sign things with
     *  the PrivateKey object returned by this signingdevice implementation.
     * @return String the name of the Provider
     */
	public String getProvider() {
		log.debug("getProvider()");	  	 
		return "BC";
	}

	/**
     * The correct authentication code is: foo123
     * 
	 * @see se.anatom.ejbca.ca.caadmin.IHardCAToken#activate(java.lang.String)
	 */
	public void activate(String authenticationcode) throws CATokenAuthenticationFailedException, CATokenOfflineException {
	    if(offline)
	      throw new CATokenOfflineException();
	
		if(authenticationcode != null && authenticationcode.equals("foo123"))
		  authenticated = true;
		else{
		  authenticated = false;
		  throw new CATokenAuthenticationFailedException("Wrong authentication code, try 'foo123'");
		}		  		
	}
	
	/**
     * 
     * 
	 * @see se.anatom.ejbca.ca.caadmin.IHardCAToken#deactivate()
	 */
	public boolean deactivate() {
	  authenticated = false;
	  
	  return true;
	}
	
}
