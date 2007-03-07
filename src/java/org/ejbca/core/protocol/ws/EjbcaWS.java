package org.ejbca.core.protocol.ws;

import java.io.IOException;
import java.math.BigInteger;
import java.rmi.RemoteException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.annotation.Resource;
import javax.ejb.CreateException;
import javax.ejb.EJBException;
import javax.ejb.FinderException;
import javax.ejb.ObjectNotFoundException;
import javax.ejb.RemoveException;
import javax.jws.WebService;
import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.http.HttpServletRequest;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.log4j.Logger;
import org.ejbca.core.EjbcaException;
import org.ejbca.core.ejb.approval.IApprovalSessionLocal;
import org.ejbca.core.ejb.approval.IApprovalSessionLocalHome;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocal;
import org.ejbca.core.ejb.authorization.IAuthorizationSessionLocalHome;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocal;
import org.ejbca.core.ejb.ca.caadmin.ICAAdminSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.model.SecConst;
import org.ejbca.core.model.approval.ApprovalException;
import org.ejbca.core.model.approval.ApprovalRequestExpiredException;
import org.ejbca.core.model.approval.WaitingForApprovalException;
import org.ejbca.core.model.authorization.AuthorizationDeniedException;
import org.ejbca.core.model.authorization.AvailableAccessRules;
import org.ejbca.core.model.ca.AuthLoginException;
import org.ejbca.core.model.ca.AuthStatusException;
import org.ejbca.core.model.ca.IllegalKeyException;
import org.ejbca.core.model.ca.caadmin.CADoesntExistsException;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implementor of the IEjbcaWS interface.
 * 
 * @author Philip Vendil
 * $Id: EjbcaWS.java,v 1.4 2007-03-07 10:08:56 herrvendil Exp $
 */

@WebService
public class EjbcaWS implements IEjbcaWS {
	@Resource
	private WebServiceContext wsContext;	
	
	/** The maximum number of rows returned in array responses. */
	private static final int MAXNUMBEROFROWS = 100;
	
	private static final Logger log = Logger.getLogger(EjbcaWS.class);				
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#editUser(org.ejbca.core.protocol.ws.objects.UserDataVOWS)
	 */	
	public void editUser(UserDataVOWS userdata)
			throws  AuthorizationDeniedException, UserDoesntFullfillEndEntityProfile, EjbcaException, ApprovalException, WaitingForApprovalException {
		   	    
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
	}
	
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findUser(org.ejbca.core.protocol.ws.objects.UserMatch)
	 */
	
	public List<UserDataVOWS> findUser(UserMatch usermatch) throws AuthorizationDeniedException, IllegalQueryException, EjbcaException {		
    	ArrayList<UserDataVOWS> retval = null;
		try{
		  Admin admin = getAdmin();
		  
		  Query query = convertUserMatch(admin, usermatch);		  		  
		  
		  Collection result = getUserAdminSession().query(admin, query, null,null, MAXNUMBEROFROWS);
		  
		  if(result.size() > 0){
		    retval = new ArrayList<UserDataVOWS>();
		    Iterator iter = result.iterator();
		    for(int i=0; i<result.size();i++){
		    	UserDataVO userdata = (UserDataVO) iter.next();
		    	retval.add(convertUserDataVO(admin,userdata));
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#findCerts(java.lang.String, boolean)
	 */
	
	public List<Certificate> findCerts(String username, boolean onlyValid)
			throws  AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		List<Certificate> retval = null;
		try{
			Admin admin = getAdmin();
			getUserAdminSession().findUser(admin,username);
			
			Collection certs = getCertStoreSession().findCertificatesByUsername(admin,username);
			
			if(onlyValid){
				certs = returnOnlyValidCertificates(admin,certs); 
			}
			
			certs = returnOnlyAuthorizedCertificates(admin,certs);
			
			if(certs.size() > 0){
			  retval = new ArrayList<Certificate>();
			  Iterator iter = certs.iterator();
			  for(int i=0; i < certs.size(); i++){				  					
				  retval.add(new Certificate((java.security.cert.Certificate) iter.next()));
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


	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs10Req(java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	
	public Certificate pkcs10Req(String username, String password,
			String pkcs10, String hardTokenSN) throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		
		Certificate retval = null;
		
		try{
			  Admin admin = getAdmin();			  
			  
			  // check CAID
			  UserDataVO userdata = getUserAdminSession().findUser(admin,username);
			  if(userdata == null){
				  throw new NotFoundException("Error: User " + username + " doesn't exist");
			  }
			  int caid = userdata.getCAId();
			  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.CAPREFIX +caid);
			  
			  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_CREATECERTIFICATE);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_BROWSERGEN){
				  throw new EjbcaException("Error: Wrong Token Type of user, must be 'USERGENERATED' for PKCS10 requests");
			  }
			  
			  PKCS10RequestMessage pkcs10req=RequestHelper.genPKCS10RequestMessageFromPEM(pkcs10.getBytes());
		      
		      java.security.cert.Certificate cert =  getSignSession().createCertificate(admin,username,password, pkcs10req.getRequestPublicKey());
			  retval = new Certificate(cert);
			            
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#pkcs12Req(java.lang.String, java.lang.String, java.lang.String, java.lang.String, java.lang.String)
	 */
	
	public KeyStore pkcs12Req(String username, String password, String hardTokenSN, String keyspec, String keyalg) throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		KeyStore retval = null;
		
		try{
			  Admin admin = getAdmin();
			  
			  // check CAID
			  UserDataVO userdata = getUserAdminSession().findUser(admin,username);
			  if(userdata == null){
				  throw new NotFoundException("Error: User " + username + " doesn't exist");
			  }
			  int caid = userdata.getCAId();
			  getAuthorizationSession().isAuthorized(admin,AvailableAccessRules.CAPREFIX +caid);

			  getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.REGULAR_CREATECERTIFICATE);
			  
			  // Check tokentype
			  if(userdata.getTokenType() != SecConst.TOKEN_SOFT_P12){
				  throw new EjbcaException("Error: Wrong Token Type of user, must be 'P12' for PKCS12 requests");
			  }
			  
			  KeyPair keys = KeyTools.genKeys(keyspec, keyalg);
		      // Generate Certificate
		      X509Certificate cert = (X509Certificate) getSignSession().createCertificate(admin,username,password, keys.getPublic());
		      
		      // Generate Keystore
		        // Fetch CA Cert Chain.	        
		      Collection chain =  getCAAdminSession().getCAInfo(admin, caid).getCertificateChain();
		      String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
		      if (alias == null){
		    	  alias = username;
		      }	      	      
		      java.security.KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

			  retval = new KeyStore(pkcs12, password);
			  
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
			} catch (InvalidAlgorithmParameterException e) {
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeCert(java.lang.String, java.lang.String, int)
	 */
	
	public void revokeCert(String issuerDN, String certificateSN, int reason) throws AuthorizationDeniedException, NotFoundException, EjbcaException {
		
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeUser(java.lang.String, int, boolean)
	 */
	public void revokeUser(String username, int reason, boolean deleteUser)
			throws AuthorizationDeniedException, NotFoundException, EjbcaException {

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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#revokeToken(java.lang.String, int)
	 */
	
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#checkRevokationStatus(java.lang.String, java.lang.String)
	 */
	
	public RevokeStatus checkRevokationStatus(String issuerDN, String certificateSN) throws   AuthorizationDeniedException, EjbcaException {
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

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isAuthorized(java.lang.String)
	 */
	public boolean isAuthorized(String resource) throws EjbcaException{
		boolean retval = false;
		try{
		  retval = getAuthorizationSession().isAuthorized(getAdmin(), resource);	
		}catch(AuthorizationDeniedException ade){
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, isAuthorized : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#fetchUserData(java.util.List, java.lang.String)
	 */
	public List<UserDataVOWS> fetchUserData(List<Integer> userDataSourceIds, String searchString) throws UserDataSourceException, EjbcaException{
		// TODO
        return new ArrayList<UserDataVOWS>();		
	}		
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#genTokenCertificates(org.ejbca.core.protocol.ws.objects.UserDataVOWS, java.util.List, org.ejbca.core.protocol.ws.objects.HardTokenDataWS)
	 */
	
	public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userData, List<TokenCertificateRequestWS> tokenRequests, HardTokenDataWS hardTokenData) throws AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException, EjbcaException{
		// TODO
        return new ArrayList<TokenCertificateResponseWS>(); 	
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#existsHardToken(java.lang.String)
	 */
	public boolean existsHardToken(String hardTokenSN) throws EjbcaException{
		boolean retval = true;
		
		try {
			retval = this.getHardTokenSession().existsHardToken(getAdmin(), hardTokenSN);
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, existsHardToken : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenData(java.lang.String)
	 */
	public HardTokenDataWS getHardTokenData(String hardTokenSN) throws AuthorizationDeniedException, HardTokenDoesntExistsException, EjbcaException{
		HardTokenDataWS retval = null;
		
		// TODO
		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenDatas(java.lang.String)
	 */
	public List<HardTokenDataWS> getHardTokenDatas(String username) throws AuthorizationDeniedException, EjbcaException{
		List<HardTokenDataWS> retval = new  ArrayList<HardTokenDataWS>();
		
		// TODO		
		
		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#republishCertificate(java.lang.String, java.lang.String)
	 */
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws AuthorizationDeniedException, PublisherException, EjbcaException{
		// TODO
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isApproved(int)
	 */
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		int retval = 0;
		
		try {
			retval = this.getApprovalSession().isApproved(getAdmin(), approvalId);
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}
	
	private Admin getAdmin() throws AuthorizationDeniedException, ClassCastException, CreateException, NamingException{
  		  MessageContext msgContext = wsContext.getMessageContext();
		  HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
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
	}
	
	/**
	 * Help metod returning a subset of certificates containing only valid certificates
	 * expiredate and revokation status is checked.
	 * @throws NamingException 
	 * @throws CreateException 
	 * @throws ClassCastException 
	 */
	private Collection returnOnlyValidCertificates(Admin admin, Collection certs) throws ClassCastException, CreateException, NamingException {
       ArrayList<X509Certificate> retval = new ArrayList<X509Certificate>();
       
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
		ArrayList<X509Certificate> retval = new ArrayList<X509Certificate>();
		
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
	
	private IApprovalSessionLocal approvalsession = null;
	private IApprovalSessionLocal getApprovalSession() {
		try{
			if(approvalsession == null){
				Context context = new InitialContext();
				approvalsession = ((IApprovalSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"ApprovalSessionLocal"), IApprovalSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Approval Session Bean",e);
			throw new EJBException(e);
		}
		return approvalsession;
	}


}
