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
package org.ejbca.core.protocol.ws;

import java.rmi.RemoteException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.TreeMap;

import javax.ejb.CreateException;
import javax.ejb.FinderException;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.util.EjbRemoteHelper;
import org.ejbca.core.protocol.ws.common.HardTokenConstants;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.NameAndId;
import org.ejbca.core.protocol.ws.objects.PINDataWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.util.CertTools;
import org.ejbca.util.query.Query;

/** Helper class for other classes that wants to call remote EJBs.
 * Methods for fetching ejb session bean interfaces.
 * 
 * @version $Id$
 */
public class EjbcaWSHelper extends EjbRemoteHelper {

	private static final Logger log = Logger.getLogger(EjbcaWSHelper.class);				

	//
	// Helper methods for various tasks done from the WS interface
	//
	protected Admin getAdmin(WebServiceContext wsContext) throws AuthorizationDeniedException, EjbcaException{		  
		  return getAdmin(false, wsContext);
	}
	
	protected Admin getAdmin(boolean allowNonAdmins, WebServiceContext wsContext) throws AuthorizationDeniedException, EjbcaException {
		Admin admin = null;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		try {
			MessageContext msgContext = wsContext.getMessageContext();
			HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
			X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

			if(certificates == null){
				throw new AuthorizationDeniedException("Error no client certificate recieved used for authentication.");
			}

			admin = new Admin(certificates[0]);
			// Check that user have the administrator flag set.
			if(!allowNonAdmins){
				ejbhelper.getUserAdminSession().checkIfCertificateBelongToAdmin(admin, CertTools.getSerialNumber(certificates[0]), CertTools.getIssuerDN(certificates[0]));
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_ADMINISTRATOR);
			}

			RevokedCertInfo revokeResult =  ejbhelper.getCertStoreSession().isRevoked(new Admin(Admin.TYPE_INTERNALUSER),CertTools.getIssuerDN(certificates[0]), CertTools.getSerialNumber(certificates[0]));
			if(revokeResult == null || revokeResult.getReason() != RevokedCertInfo.NOT_REVOKED){
				throw new AuthorizationDeniedException("Error administrator certificate doesn't exist or is revoked.");
			}
		} catch (RemoteException e) {
			log.error("EJBCA WebService error: ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error: ",e);
			throw new EjbcaException(e.getMessage());
		}

		return admin;
	}
	
	/**
	 * Method used to check if the admin is an administrator
	 * i.e have administrator flag set and access to resource
	 * /administrator
	 * @return
	 * @throws AuthorizationDeniedException 
	 */
	protected boolean isAdmin(WebServiceContext wsContext) throws EjbcaException {
		boolean retval = false;
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

		if(certificates == null){
			throw new EjbcaException("Error no client certificate recieved used for authentication.");
		}

		Admin admin = new Admin(certificates[0]);
		try{
			ejbhelper.getUserAdminSession().checkIfCertificateBelongToAdmin(admin, CertTools.getSerialNumber(certificates[0]), CertTools.getIssuerDN(certificates[0]));
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_ADMINISTRATOR);
			retval = true;
		}catch(AuthorizationDeniedException e){
		} catch (CreateException e) {			
			log.error("Error checking if isAdmin: ", e);
		} catch (RemoteException e) {
			log.error("EJBCA WebService error, isAdmin : ",e);
			throw new EjbcaException(e.getMessage());
		} 
		
		return retval;
	}

	protected void isAuthorizedToRepublish(Admin admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException, RemoteException{
		try {
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWCERTIFICATE);
			UserDataVO userdata = null;
			try {
				userdata = ejbhelper.getUserAdminSession().findUser(admin, username);
			} catch (FinderException e) {
				throw new EjbcaException("Error the  user doesn't seem to exist.");
			}
			if(userdata == null){
				throw new EjbcaException("Error the  user doesn't seem to exist.");
			}
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.VIEW_RIGHTS);
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + caid );		
		} catch (RemoteException e) {
			throw new EjbcaException(e);
		} catch (CreateException e) {
			throw new EjbcaException(e);
		}

	}
	
	
	protected void isAuthorizedToHardTokenData(Admin admin, String username, boolean viewPUKData) throws AuthorizationDeniedException, EjbcaException, RemoteException {
		try {
			EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWHARDTOKENS);
			UserDataVO userdata = null;
			boolean userExists = false;
			try {
				userdata = ejbhelper.getUserAdminSession().findUser(admin, username);
				if(userdata != null){
					userExists = true;
				}
			} catch (FinderException e) {
				// Do nothing
			}

			ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWHARDTOKENS);
			if(viewPUKData){
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWPUKS);
			}

			if(userExists){		
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.HARDTOKEN_RIGHTS);
				if(viewPUKData){
					ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.HARDTOKEN_PUKDATA_RIGHTS);			
				}
			}

		} catch (RemoteException e) {
			throw new EjbcaException(e);
		} catch (CreateException e) {
			throw new EjbcaException(e);
		}		
	}
	
	protected UserDataVO convertUserDataVOWS(Admin admin, UserDataVOWS userdata) throws EjbcaException, ClassCastException, CreateException, NamingException, RemoteException {
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		CAInfo cainfo = ejbhelper.getCAAdminSession().getCAInfo(admin,userdata.getCaName());
		if (cainfo == null) {
			throw new EjbcaException("Error CA " + userdata.getCaName() + " doesn't exists.");
		}
		int caid = cainfo.getCAId();
		if (caid == 0) {
			throw new EjbcaException("Error CA " + userdata.getCaName() + " have caid 0, which is impossible.");
		}
		
		int endentityprofileid = ejbhelper.getRAAdminSession().getEndEntityProfileId(admin,userdata.getEndEntityProfileName());
		if(endentityprofileid == 0){
			throw new EjbcaException("Error End Entity profile " + userdata.getEndEntityProfileName() + " doesn't exists.");
		}

		int certificateprofileid = ejbhelper.getCertStoreSession().getCertificateProfileId(admin,userdata.getCertificateProfileName());
		if(certificateprofileid == 0){
			throw new EjbcaException("Error Certificate profile " + userdata.getCertificateProfileName() + " doesn't exists.");
		}
		
		int hardtokenissuerid = 0;
		if(userdata.getHardTokenIssuerName() != null){
         hardtokenissuerid = ejbhelper.getHardTokenSession().getHardTokenIssuerId(admin,userdata.getHardTokenIssuerName());
		   if(hardtokenissuerid == 0){
			  throw new EjbcaException("Error Hard Token Issuer " + userdata.getHardTokenIssuerName() + " doesn't exists.");
		   }
		}
		
		int tokenid = getTokenId(admin,userdata.getTokenType());
		if(tokenid == 0){
			throw new EjbcaException("Error Token Type  " + userdata.getTokenType() + " doesn't exists.");
		}
		
		UserDataVO userdatavo = new UserDataVO(userdata.getUsername(),
				userdata.getSubjectDN(),
				caid,
				userdata.getSubjectAltName(),
				userdata.getEmail(),
				userdata.getStatus(),
				userdata.getType(),
				endentityprofileid,
				certificateprofileid,
				null,
				null,
				tokenid,
				hardtokenissuerid,
				null);
		
		userdatavo.setPassword(userdata.getPassword());
		
		return userdatavo;
	}
	
	
	
	protected UserDataVOWS convertUserDataVO(Admin admin, UserDataVO userdata) throws EjbcaException, ClassCastException, CreateException, NamingException, RemoteException{
		String username = userdata.getUsername();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		String caname = ejbhelper.getCAAdminSession().getCAInfo(admin,userdata.getCAId()).getName();
		if(caname == null){
			String message = "Error CA id " + userdata.getCAId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(message);
		}
		
		String endentityprofilename = ejbhelper.getRAAdminSession().getEndEntityProfileName(admin,userdata.getEndEntityProfileId());
		if(endentityprofilename == null){
			String message = "Error End Entity profile id " + userdata.getEndEntityProfileId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(message);
		}

		String certificateprofilename = ejbhelper.getCertStoreSession().getCertificateProfileName(admin,userdata.getCertificateProfileId());
		if(certificateprofilename == null){
			String message = "Error Certificate profile id " + userdata.getCertificateProfileId() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(message);
		}
		
		String hardtokenissuername = null;
		if(userdata.getHardTokenIssuerId() != 0){
		   hardtokenissuername = ejbhelper.getHardTokenSession().getHardTokenIssuerAlias(admin,userdata.getHardTokenIssuerId());
		   if(hardtokenissuername == null){
			   String message = "Error Hard Token Issuer id " + userdata.getHardTokenIssuerId() + " doesn't exists. User: "+username;
			   log.error(message);
			   throw new EjbcaException(message);
		   }
		}
		
		String tokenname = getTokenName(admin,userdata.getTokenType());
		if(tokenname == null){
			String message = "Error Token Type id " + userdata.getTokenType() + " doesn't exists. User: "+username;
			log.error(message);
			throw new EjbcaException(message);
		}										
		return new UserDataVOWS(userdata.getUsername(),null,false,userdata.getDN(),caname,userdata.getSubjectAltName(),userdata.getEmail(),userdata.getStatus(),tokenname,endentityprofilename,certificateprofilename,hardtokenissuername);
	}
	
	/**
	 * Method used to convert a HardToken data to a WS version
	 * @param data
	 * @throws EjbcaException 
	 */
	protected HardTokenDataWS convertHardTokenToWS(HardTokenData data, Collection certificates, boolean includePUK) throws EjbcaException {
		HardTokenDataWS retval = new HardTokenDataWS();
		retval.setHardTokenSN(data.getTokenSN());
		retval.setLabel(data.getHardToken().getLabel());
		retval.setCopyOfSN(data.getCopyOf());
		ArrayList<String> copies = new ArrayList<String>();
		if(data.getCopies() != null){
			Iterator iter = data.getCopies().iterator();
			while(iter.hasNext()){
				copies.add((String) iter.next());

			}
		}
		retval.setCopies(copies);
		retval.setModifyTime(data.getModifyTime());
		retval.setCreateTime(data.getCreateTime());
		retval.setEncKeyKeyRecoverable(false);

		try{
			Iterator iter = certificates.iterator();
			while(iter.hasNext()){
				retval.getCertificates().add(new Certificate((java.security.cert.Certificate) iter.next()));
			}
		}catch(CertificateEncodingException e){
			log.error("EJBCA WebService error, getHardToken: ",e);
			throw new EjbcaException(e.getMessage());
		}


		if(data.getHardToken() instanceof SwedishEIDHardToken){
			SwedishEIDHardToken ht = (SwedishEIDHardToken) data.getHardToken();
			if(includePUK){
			  retval.getPinDatas().add(new PINDataWS(HardTokenConstants.PINTYPE_SIGNATURE,ht.getInitialSignaturePIN(),ht.getSignaturePUK()));
			  retval.getPinDatas().add(new PINDataWS(HardTokenConstants.PINTYPE_BASIC,ht.getInitialAuthEncPIN(),ht.getAuthEncPUK()));
			}
			retval.setTokenType(HardTokenConstants.TOKENTYPE_SWEDISHEID);
		}else
			if(data.getHardToken() instanceof EnhancedEIDHardToken){
				EnhancedEIDHardToken ht = (EnhancedEIDHardToken) data.getHardToken();
				retval.setEncKeyKeyRecoverable(ht.getEncKeyRecoverable());
				if(includePUK){
				  retval.getPinDatas().add(new PINDataWS(HardTokenConstants.PINTYPE_SIGNATURE,ht.getInitialSignaturePIN(),ht.getSignaturePUK()));
				  retval.getPinDatas().add(new PINDataWS(HardTokenConstants.PINTYPE_BASIC,ht.getInitialAuthPIN(),ht.getAuthPUK()));
				}
				retval.setTokenType(HardTokenConstants.TOKENTYPE_ENHANCEDEID);
			}else{
				throw new EjbcaException("Error: only SwedishEIDHardToken, EnhancedEIDHardToken supported.");
			}


		return retval;
	}
	
	/**
	 * Method that converts profilenames etc to corresponding Id's
	 * @param admin
	 * @param usermatch a usermatch containing names of profiles
	 * @return a query containg id's of profiles.
	 * @throws NumberFormatException
	 * @throws ClassCastException
	 * @throws CreateException
	 * @throws NamingException
	 */
	protected Query convertUserMatch(Admin admin, UserMatch usermatch) throws NumberFormatException, ClassCastException, CreateException, NamingException, RemoteException{
		Query retval = new Query(Query.TYPE_USERQUERY);		  		
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		switch(usermatch.getMatchwith()){
		  case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
			  String endentityprofilename = Integer.toString(ejbhelper.getRAAdminSession().getEndEntityProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),endentityprofilename);
			  break;
		  case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
			  String certificateprofilename = Integer.toString(ejbhelper.getCertStoreSession().getCertificateProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),certificateprofilename);
			  break;			  
		  case UserMatch.MATCH_WITH_CA:
			  String caname = Integer.toString(ejbhelper.getCAAdminSession().getCAInfo(admin,usermatch.getMatchvalue()).getCAId());
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),caname);
			  break;	
		  case UserMatch.MATCH_WITH_TOKEN:
			  String tokenname = Integer.toString(getTokenId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),tokenname);
			  break;
		  default:		
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),usermatch.getMatchvalue());
			  break;
		}
		
		
		return retval;
	}
	
	/**
	 * Help metod returning a subset of certificates containing only valid certificates
	 * expiredate and revokation status is checked.
	 * @throws NamingException 
	 * @throws CreateException 
	 * @throws ClassCastException 
	 */
	protected Collection<java.security.cert.Certificate> returnOnlyValidCertificates(Admin admin, Collection<java.security.cert.Certificate> certs) throws CreateException, NamingException, RemoteException {
     ArrayList<java.security.cert.Certificate> retval = new ArrayList<java.security.cert.Certificate>();
     EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
     Iterator<java.security.cert.Certificate> iter = certs.iterator();
     while(iter.hasNext()){
    	 java.security.cert.Certificate next = iter.next();
  	   
  	   RevokedCertInfo info = ejbhelper.getCertStoreSession().isRevoked(admin,CertTools.getIssuerDN(next),CertTools.getSerialNumber(next));
  	   if(info.getReason() == RevokedCertInfo.NOT_REVOKED){
  		   try{
  			   CertTools.checkValidity(next, new Date());
  			   retval.add(next);
  		   }catch(CertificateExpiredException e){    			   
  		   }catch (CertificateNotYetValidException e) {    			   
  		   }
  	   }
     }
	
     return retval;
	}
	
	protected Collection<java.security.cert.Certificate> returnOnlyAuthorizedCertificates(Admin admin, Collection<java.security.cert.Certificate> certs) throws RemoteException, CreateException {
		ArrayList<java.security.cert.Certificate> retval = new ArrayList<java.security.cert.Certificate>();
		EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
		Iterator<java.security.cert.Certificate> iter = certs.iterator();
		while(iter.hasNext()){
			java.security.cert.Certificate next = iter.next();
			try{
				// check that admin is autorized to CA
				int caid = CertTools.getIssuerDN(next).hashCode();		
				ejbhelper.getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
				retval.add(next);
			}catch(AuthorizationDeniedException ade){
				log.debug("findCerts : not authorized to certificate " + CertTools.getSerialNumber(next).toString(16));
			}
		}
		
		return retval;
	}
	
	
	private final String[] softtokennames = {UserDataVOWS.TOKEN_TYPE_USERGENERATED,UserDataVOWS.TOKEN_TYPE_P12,
			                                 UserDataVOWS.TOKEN_TYPE_JKS,UserDataVOWS.TOKEN_TYPE_PEM};
	private final int[] softtokenids = {SecConst.TOKEN_SOFT_BROWSERGEN,
			SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM};
	
	private int getTokenId(Admin admin, String tokenname) throws RemoteException, CreateException{
      int returnval = 0;
      
      // First check for soft token type
      for(int i=0;i< softtokennames.length;i++){
      	if(softtokennames[i].equals(tokenname)){
      		returnval = softtokenids[i];
      		break;
      	}        	
      }
      EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
      if (returnval == 0) {
           returnval = ejbhelper.getHardTokenSession().getHardTokenProfileId(admin , tokenname);
      }

      return returnval;
	}
	
	private String getTokenName(Admin admin, int tokenid) throws RemoteException, CreateException{
      String returnval = null;
      
      // First check for soft token type
      for(int i=0;i< softtokenids.length;i++){
      	if(softtokenids[i] == tokenid){
      		returnval = softtokennames[i];
      		break;
      	}        	
      }
      EjbcaWSHelper ejbhelper = new EjbcaWSHelper();
      if (returnval == null) {
           returnval = ejbhelper.getHardTokenSession().getHardTokenProfileName(admin , tokenid);
      }

      return returnval;
	}

  /**
	 * Web services does not support Collection type so convert it to array.
	 * 
	 * @param mytree TreeMap of name and id pairs to convert to an array
	 * @return array of NameAndId objects
	 */
  protected NameAndId[] convertTreeMapToArray(TreeMap<String, Integer> mytree) {
  	NameAndId[] ret = null;

		if ((mytree == null) || (mytree.size() == 0) ) {
			ret = new NameAndId[0];
		} else {
			ret = new NameAndId[mytree.size()];
			int i = 0;
			for (String name : mytree.keySet()) {
				ret[i++] = new NameAndId(name, mytree.get(name));
			}
		}
		return ret;
	}



}