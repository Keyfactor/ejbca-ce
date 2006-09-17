package org.ejbca.core.protocol.ws.services;

import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.xml.rpc.ServiceException;
import javax.xml.rpc.handler.MessageContext;
import javax.xml.rpc.server.ServiceLifecycle;
import javax.xml.rpc.server.ServletEndpointContext;

import org.apache.log4j.Logger;




/**
 * Interface the the EJBCA RA WebService. Contains the following methods:
 * 
 * editUser    : Edits/adds  userdata
 * findUser    : Retrieves the userdata for a given user.
 * findCerts   : Retrieves the certificates generated for a user.
 * pkcs10Req   : Generates a certificate using the given userdata and the public key from the PKCS10
 * pkcs12Req   : Generates a PKCS12 keystore (with the private key) using the given userdata
 * revokeCert  : Revokes the given certificate.
 * revokeUser  : Revokes all certificates for a given user, it's also possible to delete the user.
 * revokeToken : Revokes all certificates placed on a given hard token
 * checkRevokationStatus : Checks the revokation status of a certificate.
 * 
 * Observere: All methods have to be called using client authenticated https
 * otherwise will a AuthorizationDenied Exception be thrown.
 * 
 * @author Philip Vendil
 * $Id: EjbcaRAWS.java,v 1.1 2006-09-17 23:00:27 herrvendil Exp $
 */


public class EjbcaRAWS implements ServiceLifecycle {
	

	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;

	private static Logger log = Logger.getLogger(EjbcaRAWS.class);
	
	private ServletEndpointContext context = null;
	
		
	public String test(String msg) throws Exception{
		  MessageContext messageContext = context.getMessageContext();
		  HttpServletRequest request = (HttpServletRequest) messageContext.getProperty("transport.http.servletRequest");
		  X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
		  if(certificates == null){
			  System.out.println("cert is null : " + msg);
		  }else{
			  System.out.println("cert is  : " + certificates[0].getSubjectDN().toString());
		  }
		System.out.println("Test Called : " + msg);
		return msg;
	}


	/**
	 * Method that should be used to edit/add a user to the EJBCA database,
	 * if the user doesn't already exists it will be added othervise it will be
	 * overwritten.
	 * 
	 * Observe: if the user doesn't already exists, it's status will always be set to 'New'.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/create_end_entity and/or edit_end_entity
	 * - /ra_functionality/<end entity profile of user>/create_end_entity and/or edit_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param userdata contains all the information about the user about to be added.
	 * @param clearPwd indicates it the password should be stored in cleartext, requeried
	 * when creating server generated keystores.
	 * @throws RemoteException for all other errors
	 * @throws EjbcaException 
	 */	
/*
	public void editUser(UserDataVOWS userdata)
			throws RemoteException, AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {
		try{
		  Admin admin = getAdmin();
		  UserDataVO userdatavo = convertUserDataVOWS(admin, userdata);
		  
		  int caid = userdatavo.getCAId();
		  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
		  
		  if(getUserAdminSession().findUser(admin, userdatavo.getUsername()) != null){
			  log.debug("User " + userdata.getUsername() + " exists, update the userdata." );
			  getUserAdminSession().changeUser(admin,userdatavo,userdata.getClearPwd());
		  }else{
			  log.debug(" New User " + userdata.getUsername() + ", adding userdata." );
			  getUserAdminSession().addUser(admin,userdatavo,userdata.getClearPwd());
		  }
		}catch(UserDoesntFullfillEndEntityProfile e){
			throw e;
	    } catch (ClassCastException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			throw e;
		} catch (CreateException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
	    	log.error("EJBCA WebService error, editUser : ", e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			log.error("EJBCA WebService error, editUser : ",e);
			throw new EjbcaException(e.getMessage());
		} 
	}*/
	
	
	/**
	 * Retreives information about a user in the database.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /ra_functionality/<end entity profile of matching users>/view_end_entity
	 * - /ca/<ca of matching users>
	 * 
	 * @param username, the unique username to search for
	 * @return a array of UserDataVOWS objects (Max 100) containing the information about the user or null if user doesn't exists.
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws IllegalQueryException if query isn't valid
	 * @throws RemoteException for all other errors
	 * @throws EjbcaException 
	 */
	/*
	public UserDataVOWS[] findUser(UserMatch usermatch) throws RemoteException, AuthorizationDeniedException, IllegalQueryException, EjbcaException {
    	UserDataVOWS[] retval = null;
		try{
		  Admin admin = getAdmin();
		  
		  Query query = convertUserMatch(admin, usermatch);		  		  
		  
		  Collection result = getUserAdminSession().query(admin, query, null,null, MAXNUMBEROFROWS);
		  
		  if(result.size() > 0){
		    retval = new UserDataVOWS[result.size()];
		    Iterator iter = result.iterator();
		    for(int i=0; i<result.size();i++){
		    	UserDataVO userdata = (UserDataVO) iter.next();
		    	retval[i] = convertUserDataVO(admin,userdata);
		    }		    
		  }
		  
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, findUser : ",e);
			throw new EjbcaException(e.getMessage());
		}
		return retval;
	}
*/
	/**
	 * Retreives a collection of certificates generated for a user.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /ra_functionality/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param username a unique username 
	 * @param onlyValid only return valid certs not revoked or expired ones.
	 * @return a collection of X509Certificates or null if no certificates could be found
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws RemoteException for all other errors
	 * @throws EjbcaException 
	 */
	/*
	public Certificate[] findCerts(String username, boolean onlyValid)
			throws RemoteException,  AuthorizationDeniedException, NotFoundException, EjbcaException {
		

		
		Certificate[] retval = null;
		try{
			Admin admin = getAdmin();
			getUserAdminSession().findUser(admin,username);
			
			Collection certs = getCertStoreSession().findCertificatesByUsername(admin,username);
			
			if(onlyValid){
				certs = returnOnlyValidCertificates(admin,certs); 
			}
			
			certs = returnOnlyAuthorizedCertificates(admin,certs);
			
			if(certs.size() > 0){
			  retval = new Certificate[certs.size()];
			  Iterator iter = certs.iterator();
			  for(int i=0; i < certs.size(); i++){				  					
				  retval[i] = new Certificate((java.security.cert.Certificate) iter.next());
			  }
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
		    log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, findCerts : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}

*/
	/**
	 * Method to use to generate a certificate for a user. The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add nonexisting users.
	 * 
	 * Observe, the user must first have added/set the status to new with edituser command
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /ra_functionality/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param pkcs10 the PKCS10 (only the public key is used.)
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplyfy revokation of a tokens
	 * certificates. Use null if no hardtokenSN should be assiciated with the certificate.
	 * @return the generated certificate.
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws RemoteException for all other errors
	 */
	/*
	public org.ejbca.core.protocol.ws.Certificate pkcs10Req(String username, String password,
			String pkcs10, String hardTokenSN) throws RemoteException, AuthorizationDeniedException, NotFoundException, EjbcaException {
		org.ejbca.core.protocol.ws.Certificate retval = null;
		

		
		try{
			  Admin admin = getAdmin();			  
			  
			  // check CAID
			  UserDataVO userdata = getUserAdminSession().findUser(admin,username);
			  if(userdata == null){
				  throw new NotFoundException("Error: User " + username + " doesn't exist");
			  }
			  int caid = userdata.getCAId();
			  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
				  throw new EjbcaException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10 requests");
			  }
			  
			  PKCS10RequestMessage pkcs10req=RequestHelper.genPKCS10RequestMessageFromPEM(pkcs10.getBytes());
		      
		      java.security.cert.Certificate cert =  getSignSession().createCertificate(admin,username,password, pkcs10req.getRequestPublicKey());
			  retval = new org.ejbca.core.protocol.ws.Certificate(cert);
			            
			  if(hardTokenSN != null){ 
				  getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,(X509Certificate) cert);				  
			  }
			  
			}catch(AuthorizationDeniedException ade){
				throw ade;
			} catch (ClassCastException e) {
			    log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CreateException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
		        throw new EjbcaException(e.getMessage());
			} catch (NamingException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (InvalidKeyException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (ObjectNotFoundException e) {
				throw new NotFoundException(e.getMessage());
			} catch (AuthStatusException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (AuthLoginException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (IllegalKeyException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CADoesntExistsException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NoSuchAlgorithmException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NoSuchProviderException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CertificateEncodingException e) {
				log.error("EJBCA WebService error, pkcs10Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (FinderException e) {
				new NotFoundException(e.getMessage());
			}

		return retval;
	}
*/
	/**
	 * Method to use to generate a server generated keystore. The method must be preceded by
	 * a editUser call, either to set the userstatus to 'new' or to add nonexisting users and
	 * the users token should be set to SecConst.TOKEN_SOFT_P12.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/view_end_entity
	 * - /ra_functionality/<end entity profile of the user>/view_end_entity
	 * - /ca/<ca of user>
	 * 
	 * @param username the unique username
	 * @param password the password sent with editUser call
	 * @param hardTokenSN If the certificate should be connected with a hardtoken, it is
	 * possible to map it by give the hardTokenSN here, this will simplyfy revokation of a tokens
	 * certificates. Use null if no hardtokenSN should be assiciated with the certificate.
	 * @param keysize that the generated RSA should have.
	 * @return the generated keystore
	 * @throws AuthorizationDeniedException if client isn't authorized to request
	 * @throws NotFoundException if user cannot be found
	 * @throws RemoteException for all other errors
	 */
	/*
	public org.ejbca.core.protocol.ws.KeyStore pkcs12Req(String username, String password, String hardTokenSN, int keysize) throws RemoteException, AuthorizationDeniedException, NotFoundException, EjbcaException {
		org.ejbca.core.protocol.ws.KeyStore retval = null;
		

		
		try{
			  Admin admin = getAdmin();
			  
			  // check CAID
			  UserDataVO userdata = getUserAdminSession().findUser(admin,username);
			  if(userdata == null){
				  throw new NotFoundException("Error: User " + username + " doesn't exist");
			  }
			  int caid = userdata.getCAId();
			  getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.CAPREFIX +caid);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_P12){
				  throw new EjbcaException("Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests");
			  }
			  
			  KeyPair keys = KeyTools.genKeys(keysize);
		      // Generate Certificate
		      X509Certificate cert = (X509Certificate) getSignSession().createCertificate(admin,username,password, keys.getPublic());
		      
		      // Generate Keystore
		        // Fetch CA Cert Chain.	        
		      Collection chain =  getCAAdminSession().getCAInfo(admin, caid).getCertificateChain();
		      String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
		      if (alias == null){
		    	  alias = username;
		      }	      	      
		      KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

			  retval = new org.ejbca.core.protocol.ws.KeyStore(pkcs12, password);
			  
			  if(hardTokenSN != null){ 
				  getHardTokenSession().addHardTokenCertificateMapping(admin,hardTokenSN,cert);				  
			  }
			  
			}catch(AuthorizationDeniedException ade){
				throw ade;
			} catch (ClassCastException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CreateException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NamingException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (ObjectNotFoundException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (AuthStatusException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (AuthLoginException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (IllegalKeyException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CADoesntExistsException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NoSuchAlgorithmException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NoSuchProviderException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CertificateEncodingException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (FinderException e) {
				new NotFoundException(e.getMessage());
			} catch (KeyStoreException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CertificateException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (InvalidKeySpecException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (IOException e) {
				log.error("EJBCA WebService error, pkcs12Req : ",e);
			    throw new EjbcaException(e.getMessage());
			}
			
			return retval;
	}
*/
	/**
	 * Method used to revoke a certificate.
	 * 
	 * * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /ra_functionality/<end entity profile of the user owning the cert>/revoke_end_entity
	 * - /ca/<ca of certificate>
	 * 
	 * @param issuerDN of the certificate to revoke
	 * @param certificateSN of the certificate to revoke
	 * @param reason for revokation, one of RevokedCertInfo.REVOKATION_REASON_ constants
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if certificate doesn't exist
	 * @throws RemoteException for all other errors
	 */
	/*
	public void revokeCert(String issuerDN, String certificateSN, int reason) throws RemoteException, AuthorizationDeniedException, NotFoundException, EjbcaException {
		

		
		try{
			Admin admin = getAdmin();
			BigInteger serno = new BigInteger(certificateSN,16);
			String username = getCertStoreSession().findUsernameByCertSerno(admin,serno,issuerDN);
			
			// check that admin is autorized to CA
			int caid = CertTools.stringToBCDNString(issuerDN).hashCode();		
			getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);			  
			
			getUserAdminSession().revokeCert(admin,serno, issuerDN, username,  reason);
			
			}catch(AuthorizationDeniedException e){
				throw e;
			} catch (ClassCastException e) {
				log.error("EJBCA WebService error, revokeCert : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CreateException e) {
				log.error("EJBCA WebService error, revokeCert : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NamingException e) {
				log.error("EJBCA WebService error, revokeCert : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (FinderException e) {
				throw new NotFoundException(e.getMessage());
			} 											
	}
*/
	/**
	 * Method used to revoke all a users certificates. It is also possible to delete
	 * a user after all certificates have been revoked.
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /ra_functionality/<end entity profile of the user>/revoke_end_entity
	 * - /ca/<ca of users certificate>
	 * 
	 * @param username unique username i EJBCA
	 * @param reasonfor revokation, one of RevokedCertInfo.REVOKATION_REASON_ constants
	 * @param deleteUser deletes the users after all the certificates have been revoked.
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if user doesn't exist
	 * @throws RemoteException for all other errors
	 *//*
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws RemoteException, AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		
		try{
			Admin admin = getAdmin();
			
			// check CAID
			UserDataVO userdata = getUserAdminSession().findUser(admin,username);
			if(userdata == null){
				throw new NotFoundException("Error: User " + username + " doesn't exist");
			}
			int caid = userdata.getCAId();
			getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);						
			
			getUserAdminSession().revokeUser(admin,username,reason);
			if(deleteUser){
				getUserAdminSession().deleteUser(admin,username);
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		} catch (NotFoundException e) {
			throw e;
		} catch (RemoveException e) {
			log.error("EJBCA WebService error, revokeUser : ",e);
			throw new EjbcaException(e.getMessage());
		}

	}
*/
	/**
	 * Method used to revoke all certificates mapped to one hardtoken.
	 *
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ra_functionality/revoke_end_entity
	 * - /ra_functionality/<end entity profile of the user owning the token>/revoke_end_entity
	 * - /ca/<ca of certificates on token>
	 * 
	 * @param hardTokenSN of the hardTokenSN
	 * @param reasonfor revokation, one of RevokedCertInfo.REVOKATION_REASON_ constants
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws NotFoundException if token doesn't exist
	 * @throws RemoteException for all other errors
	 */
	/*
	public void revokeToken(String hardTokenSN, int reason)
			throws RemoteException, AuthorizationDeniedException, NotFoundException, EjbcaException {

		
		try{
			Admin admin = getAdmin();
			Collection certs = getHardTokenSession().findCertificatesInHardToken(admin,hardTokenSN);
			Iterator iter = certs.iterator();
			String username = null;
			while(iter.hasNext()){
				X509Certificate next = (X509Certificate) iter.next();
				if(username == null){
					username = getCertStoreSession().findUsernameByCertSerno(admin,next.getSerialNumber(),next.getIssuerDN().toString());
				}
				
				// check that admin is autorized to CA
				int caid = CertTools.stringToBCDNString(next.getIssuerDN().toString()).hashCode();		
				getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
				
				getUserAdminSession().revokeCert(admin,next.getSerialNumber(),next.getIssuerDN().toString(),username,reason);
			}
		}catch(AuthorizationDeniedException e){
			throw e;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			throw new NotFoundException(e.getMessage());
		}	

	}
*/
	/**
	 * Method returning the revokestatus for given user
	 * 
	 * Authorization requirements: the client certificate must have the following priviledges set
	 * - Administrator flag set
	 * - /administrator
	 * - /ca/<ca of certificate>
	 * 
	 * @param issuerDN 
	 * @param certificateSN a hexadecimal string
	 * @return the revokestatus of null i certificate doesn't exists.
	 * @throws AuthorizationDeniedException if client isn't authorized.
	 * @throws RemoteException for other exceptions 
	 * @see org.ejbca.core.protocol.ws.RevokeStatus
	 */
	/*
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws RemoteException, AuthorizationDeniedException, EjbcaException {
		RevokeStatus retval = null;

		
		try{
		  Admin admin = getAdmin();		  
		  
		  // check that admin is autorized to CA
		  int caid = CertTools.stringToBCDNString(issuerDN).hashCode();		
		  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
		  
		  RevokedCertInfo certinfo = getCertStoreSession().isRevoked(admin,issuerDN,new BigInteger(certificateSN,16));		  
		  retval = new RevokeStatus(certinfo,issuerDN);
		}catch(AuthorizationDeniedException ade){
			throw ade;
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, checkRevokationStatus : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		return retval;
	}	
*/
	/**
	 * Class used to clear message context
	 */
	
	public void destroy() {
		context = null;
	}

	/**
	 * Class used to set message context.
	 */
	public void init(Object context) throws ServiceException {
		this.context = (ServletEndpointContext) context;	
	}
/*
	private Admin getAdmin() throws AuthorizationDeniedException, ClassCastException, CreateException, NamingException{
		  MessageContext messageContext = context.getMessageContext();
		  HttpServletRequest request = (HttpServletRequest) messageContext.getProperty("transport.http.servletRequest");
		  X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");
		  if(certificates == null){
			  throw new AuthorizationDeniedException("Error no client certificate recieved used for authentication.");
		  }
		  
		  Admin admin = new Admin(certificates[0]);
			// Check that user have the administrator flag set.
		  getUserAdminSession().checkIfCertificateBelongToAdmin(admin, certificates[0].getSerialNumber(), certificates[0].getIssuerDN().toString());
		  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_ADMINISTRATOR);
		  
			
		  RevokedCertInfo revokeResult =  getCertStoreSession().isRevoked(new Admin(Admin.TYPE_INTERNALUSER),CertTools.stringToBCDNString(certificates[0].getIssuerDN().toString()), certificates[0].getSerialNumber());
		  if(revokeResult == null || revokeResult.getReason() != RevokedCertInfo.NOT_REVOKED){
			  throw new AuthorizationDeniedException("Error Signer certificate doesn't exist or is revoked.");
		  }
		  
		  return admin;
	}

	private UserDataVO convertUserDataVOWS(Admin admin, UserDataVOWS userdata) throws EjbcaException, ClassCastException, CreateException, NamingException{
		   
		int caid = getCAAdminSession().getCAInfo(admin,userdata.getCaName()).getCAId();
		if(caid == 0){
			throw new EjbcaException("Error CA " + userdata.getCaName() + " doesn't exists.");
		}
		
		int endentityprofileid = getRAAdminSession().getEndEntityProfileId(admin,userdata.getEndEntityProfileName());
		if(endentityprofileid == 0){
			throw new EjbcaException("Error End Entity profile " + userdata.getEndEntityProfileName() + " doesn't exists.");
		}

		int certificateprofileid = getCertStoreSession().getCertificateProfileId(admin,userdata.getCertificateProfileName());
		if(certificateprofileid == 0){
			throw new EjbcaException("Error Certificate profile " + userdata.getCertificateProfileName() + " doesn't exists.");
		}
		
		int hardtokenissuerid = 0;
		if(userdata.getHardTokenIssuerName() != null){
           hardtokenissuerid = getHardTokenSession().getHardTokenIssuerId(admin,userdata.getHardTokenIssuerName());
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
	
	private UserDataVOWS convertUserDataVO(Admin admin, UserDataVO userdata) throws EjbcaException, ClassCastException, CreateException, NamingException{
		
		String caname = getCAAdminSession().getCAInfo(admin,userdata.getCAId()).getName();
		if(caname == null){
			throw new EjbcaException("Error CA id " + userdata.getCAId() + " doesn't exists.");
		}
		
		String endentityprofilename = getRAAdminSession().getEndEntityProfileName(admin,userdata.getEndEntityProfileId());
		if(endentityprofilename == null){
			throw new EjbcaException("Error End Entity profile id " + userdata.getEndEntityProfileId() + " doesn't exists.");
		}

		String certificateprofilename = getCertStoreSession().getCertificateProfileName(admin,userdata.getCertificateProfileId());
		if(certificateprofilename == null){
			throw new EjbcaException("Error Certificate profile id" + userdata.getCertificateProfileId() + " doesn't exists.");
		}
		
		String hardtokenissuername = null;
		if(userdata.getHardTokenIssuerId() != 0){
		   hardtokenissuername = getHardTokenSession().getHardTokenIssuerAlias(admin,userdata.getHardTokenIssuerId());
		   if(hardtokenissuername == null){
			  throw new EjbcaException("Error Hard Token Issuer id " + userdata.getHardTokenIssuerId() + " doesn't exists.");
		   }
		}
		
		String tokenname = getTokenName(admin,userdata.getTokenType());
		if(tokenname == null){
			throw new EjbcaException("Error Token Type id " + userdata.getTokenType() + " doesn't exists.");
		}										
		return new UserDataVOWS(userdata.getUsername(),null,false,userdata.getDN(),caname,userdata.getSubjectAltName(),userdata.getEmail(),userdata.getStatus(),tokenname,endentityprofilename,certificateprofilename,hardtokenissuername);
	}*/
	
	/**
	 * Method that converts profilenames etc to corresponding Id's
	 * @param admin
	 * @param usermatch a usermatch containing names of profiles
	 * @return a query containg id's of profiles.
	 * @throws NumberFormatException
	 * @throws ClassCastException
	 * @throws CreateException
	 * @throws NamingException
	 *//*
	private Query convertUserMatch(Admin admin, UserMatch usermatch) throws NumberFormatException, ClassCastException, CreateException, NamingException{
		Query retval = new Query(Query.TYPE_USERQUERY);		  		
		
		switch(usermatch.getMatchwith()){
		  case UserMatch.MATCH_WITH_ENDENTITYPROFILE:
			  String endentityprofilename = Integer.toString(getRAAdminSession().getEndEntityProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),endentityprofilename);
			  break;
		  case UserMatch.MATCH_WITH_CERTIFICATEPROFILE:
			  String certificateprofilename = Integer.toString(getCertStoreSession().getCertificateProfileId(admin,usermatch.getMatchvalue()));
			  retval.add(usermatch.getMatchwith(),usermatch.getMatchtype(),certificateprofilename);
			  break;			  
		  case UserMatch.MATCH_WITH_CA:
			  String caname = Integer.toString(getCAAdminSession().getCAInfo(admin,usermatch.getMatchvalue()).getCAId());
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
	}*/
	
	/**
	 * Help metod returning a subset of certificates containing only valid certificates
	 * expiredate and revokation status is checked.
	 * @throws NamingException 
	 * @throws CreateException 
	 * @throws ClassCastException 
	 *//*
	private Collection returnOnlyValidCertificates(Admin admin, Collection certs) throws ClassCastException, CreateException, NamingException {
       ArrayList retval = new ArrayList();
       
       Iterator iter = certs.iterator();
       while(iter.hasNext()){
    	   X509Certificate next = (X509Certificate) iter.next();
    	   
    	   RevokedCertInfo info = getCertStoreSession().isRevoked(admin,next.getIssuerDN().toString(),next.getSerialNumber());
    	   if(info.getReason() == RevokedCertInfo.NOT_REVOKED){
    		   try{
    			   next.checkValidity();
    			   retval.add(next);
    		   }catch(CertificateExpiredException e){    			   
    		   }catch (CertificateNotYetValidException e) {    			   
    		   }
    	   }
       }
	
       return retval;
	}
	
	private Collection returnOnlyAuthorizedCertificates(Admin admin, Collection certs) {
		ArrayList retval = new ArrayList();
		
		Iterator iter = certs.iterator();
		while(iter.hasNext()){
			X509Certificate next = (X509Certificate) iter.next();
			
			try{
				// check that admin is autorized to CA
				int caid = CertTools.stringToBCDNString(next.getIssuerDN().toString()).hashCode();		
				getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
				retval.add(next);
			}catch(AuthorizationDeniedException ade){
				log.debug("findCerts : not authorized to certificate " + next.getSerialNumber().toString(16));
			}
		}
		
		return retval;
	}
	
	
	private final String[] softtokennames = {UserDataVOWS.TOKEN_TYPE_USERGENERATED,UserDataVOWS.TOKEN_TYPE_P12,
			                                 UserDataVOWS.TOKEN_TYPE_JKS,UserDataVOWS.TOKEN_TYPE_PEM};
	private final int[] softtokenids = {SecConst.TOKEN_SOFT_BROWSERGEN,
			SecConst.TOKEN_SOFT_P12, SecConst.TOKEN_SOFT_JKS, SecConst.TOKEN_SOFT_PEM};
	
	private int getTokenId(Admin admin, String tokenname){
        int returnval = 0;
        
        // First check for soft token type
        for(int i=0;i< softtokennames.length;i++){
        	if(softtokennames[i].equals(tokenname)){
        		returnval = softtokenids[i];
        		break;
        	}        	
        }

        if (returnval == 0) {
             returnval = getHardTokenSession().getHardTokenProfileId(admin , tokenname);
        }

        return returnval;
	}
	
	private String getTokenName(Admin admin, int tokenid){
        String returnval = null;
        
        // First check for soft token type
        for(int i=0;i< softtokenids.length;i++){
        	if(softtokenids[i] == tokenid){
        		returnval = softtokennames[i];
        		break;
        	}        	
        }

        if (returnval == null) {
             returnval = getHardTokenSession().getHardTokenProfileName(admin , tokenid);
        }

        return returnval;
	}
	
	private ICAAdminSessionLocal caadminsession = null;
	private ICAAdminSessionLocal getCAAdminSession() throws ClassCastException, CreateException, NamingException{ 		
	    if(caadminsession == null){	  
	    	Context context = new InitialContext();	    	
	    	caadminsession = ((ICAAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	    	"CAAdminSessionLocal"), ICAAdminSessionLocalHome.class)).create();   
	    }
	    return caadminsession;
	}
	
	private IRaAdminSessionLocal raadminsession = null;
	private IRaAdminSessionLocal getRAAdminSession() throws ClassCastException, CreateException, NamingException{
		if(raadminsession == null){
		  Context context = new InitialContext();
	      raadminsession = ((IRaAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
	      "RaAdminSessionLocal"), IRaAdminSessionLocalHome.class)).create();    	           	           	        
		}
		return raadminsession;
	}
	
	private ICertificateStoreSessionLocal certificatestoresession = null;
	private ICertificateStoreSessionLocal getCertStoreSession() throws ClassCastException, CreateException, NamingException{
		if(certificatestoresession == null){
			Context context = new InitialContext();
			certificatestoresession = ((ICertificateStoreSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
			"CertificateStoreSessionLocal"), ICertificateStoreSessionLocalHome.class)).create();    	           	           	        
		}
		return certificatestoresession;
	}
	
	private ISignSessionLocal signsession = null;
	private ISignSessionLocal getSignSession() throws ClassCastException, CreateException, NamingException{
		if(signsession == null){
			Context context = new InitialContext();
			signsession = ((ISignSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
			"SignSessionLocal"), ISignSessionLocalHome.class)).create();    	           	           	        
		}
		return signsession;
	}
	
	private IUserAdminSessionLocal usersession = null;
	private IUserAdminSessionLocal getUserAdminSession() {
		try{
			if(usersession == null){
				Context context = new InitialContext();
				usersession = ((IUserAdminSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"UserAdminSessionLocal"), IUserAdminSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing User Admin Session Bean",e);
			throw new EJBException(e);
		}
		return usersession;
	}
	
	private IHardTokenSessionLocal hardtokensession = null;
	private IHardTokenSessionLocal getHardTokenSession() {
		try{
			if(hardtokensession == null){
				Context context = new InitialContext();
				hardtokensession = ((IHardTokenSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"HardTokenSessionLocal"), IHardTokenSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Hard Token Session Bean",e);
			throw new EJBException(e);
		}
		return hardtokensession;
	}
	
	private IAuthorizationSessionLocal authsession = null;
	private IAuthorizationSessionLocal getAuthorizationSession() {
		try{
			if(authsession == null){
				Context context = new InitialContext();
				authsession = ((IAuthorizationSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"AuthorizationSessionLocal"), IAuthorizationSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Authorization Session Bean",e);
			throw new EJBException(e);
		}
		return authsession;
	}

*/

 




}
