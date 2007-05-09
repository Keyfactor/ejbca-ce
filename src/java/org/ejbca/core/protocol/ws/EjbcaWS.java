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
import java.util.Date;
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
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocal;
import org.ejbca.core.ejb.ca.publisher.IPublisherSessionLocalHome;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocal;
import org.ejbca.core.ejb.ca.sign.ISignSessionLocalHome;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocal;
import org.ejbca.core.ejb.ca.store.ICertificateStoreSessionLocalHome;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocal;
import org.ejbca.core.ejb.hardtoken.IHardTokenSessionLocalHome;
import org.ejbca.core.ejb.log.ILogSessionLocal;
import org.ejbca.core.ejb.log.ILogSessionLocalHome;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocal;
import org.ejbca.core.ejb.ra.IUserAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocal;
import org.ejbca.core.ejb.ra.raadmin.IRaAdminSessionLocalHome;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocal;
import org.ejbca.core.ejb.ra.userdatasource.IUserDataSourceSessionLocalHome;
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
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.publisher.PublisherException;
import org.ejbca.core.model.ca.store.CertReqHistory;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.hardtoken.HardTokenData;
import org.ejbca.core.model.hardtoken.HardTokenDoesntExistsException;
import org.ejbca.core.model.hardtoken.HardTokenExistsException;
import org.ejbca.core.model.hardtoken.types.EnhancedEIDHardToken;
import org.ejbca.core.model.hardtoken.types.HardToken;
import org.ejbca.core.model.hardtoken.types.SwedishEIDHardToken;
import org.ejbca.core.model.log.Admin;
import org.ejbca.core.model.log.LogEntry;
import org.ejbca.core.model.ra.NotFoundException;
import org.ejbca.core.model.ra.UserDataConstants;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.model.ra.raadmin.UserDoesntFullfillEndEntityProfile;
import org.ejbca.core.model.ra.userdatasource.MultipleMatchException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceException;
import org.ejbca.core.model.ra.userdatasource.UserDataSourceVO;
import org.ejbca.core.protocol.PKCS10RequestMessage;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.core.protocol.ws.common.HardTokenConstants;
import org.ejbca.core.protocol.ws.common.IEjbcaWS;
import org.ejbca.core.protocol.ws.objects.Certificate;
import org.ejbca.core.protocol.ws.objects.HardTokenDataWS;
import org.ejbca.core.protocol.ws.objects.KeyStore;
import org.ejbca.core.protocol.ws.objects.PINDataWS;
import org.ejbca.core.protocol.ws.objects.RevokeStatus;
import org.ejbca.core.protocol.ws.objects.TokenCertificateRequestWS;
import org.ejbca.core.protocol.ws.objects.TokenCertificateResponseWS;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;
import org.ejbca.core.protocol.ws.objects.UserDataVOWS;
import org.ejbca.core.protocol.ws.objects.UserMatch;
import org.ejbca.ui.web.RequestHelper;
import org.ejbca.util.CertTools;
import org.ejbca.util.KeyTools;
import org.ejbca.util.passgen.PasswordGeneratorFactory;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;

/**
 * Implementor of the IEjbcaWS interface.
 * 
 * @author Philip Vendil
 * $Id: EjbcaWS.java,v 1.12 2007-05-09 09:29:11 herrvendil Exp $
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

			if(reason == RevokedCertInfo.NOT_REVOKED){
				java.security.cert.Certificate cert = getCertStoreSession().findCertificateByIssuerAndSerno(admin, issuerDN, serno);
				if(cert == null){
					throw new NotFoundException("Error: certificate with issuerdn " + issuerDN + " and serial number " + serno + " couldn't be found in database.");
				}
				CertificateInfo certInfo = getCertStoreSession().getCertificateInfo(admin, CertTools.getCertFingerprintAsString(cert.getEncoded()));
				if(certInfo.getRevocationReason()== RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD){
					getUserAdminSession().unRevokeCert(admin, serno, issuerDN, username);
				}else{
					throw new EjbcaException("Error: Status is NOT 'certificate hold' for certificate with serial number " + serno + " and issuer DN " + issuerDN);
				}
			}else{			
				getUserAdminSession().revokeCert(admin,serno, issuerDN, username,  reason);
			}
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
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, revokeCert : ",e);
			throw new EjbcaException(e.getMessage());
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
		}  catch (FinderException e) {
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
				if(reason == RevokedCertInfo.NOT_REVOKED){
					String issuerDN = CertTools.getIssuerDN(next);
					BigInteger serno = next.getSerialNumber();

					CertificateInfo certInfo = getCertStoreSession().getCertificateInfo(admin, CertTools.getCertFingerprintAsString(next.getEncoded()));
					if(certInfo.getRevocationReason()== RevokedCertInfo.REVOKATION_REASON_CERTIFICATEHOLD){
						getUserAdminSession().unRevokeCert(admin, serno, issuerDN, username);
					}else{
						throw new EjbcaException("Error: Status is NOT 'certificate hold' for certificate with serial number " + serno + " and issuer DN " + issuerDN);
					}
				}else{
				  getUserAdminSession().revokeCert(admin,next.getSerialNumber(),next.getIssuerDN().toString(),username,reason);
				}
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
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, revokeToken : ",e);
			throw new EjbcaException(e.getMessage());
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
		} 
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#fetchUserData(java.util.List, java.lang.String)
	 */
	public List<UserDataSourceVOWS> fetchUserData(List<String> userDataSourceNames, String searchString) throws UserDataSourceException, EjbcaException{
	    	// No authorization needed for this call
		ArrayList<UserDataSourceVOWS> retval = new ArrayList<UserDataSourceVOWS>();
		
		try {	
			ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();

			Iterator iter = userDataSourceNames.iterator();
			while(iter.hasNext()){
				String name = (String) iter.next();
				int id = getUserDataSourceSession().getUserDataSourceId(getAdmin(), name);
				if(id != 0){
					userDataSourceIds.add(new Integer(id));
				}else{
					log.error("Error User Data Source with name : " + name + " doesn't exist.");
				}
			}

			iter = getUserDataSourceSession().fetch(getAdmin(), userDataSourceIds, searchString).iterator();
			while(iter.hasNext()){
				UserDataSourceVO next = (UserDataSourceVO) iter.next();
				retval.add(new UserDataSourceVOWS(convertUserDataVO(getAdmin(), next.getUserDataVO()),next.getIsFieldModifyableSet()));
			}
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, fetchUserData : ",e);
			throw new EjbcaException(e.getMessage());
		}
		
		
        return retval;		
	}		
	
	/**
	 * @throws NamingException 
	 * @throws CreateException 
	 * @throws ApprovalException 
	 * @throws UserDoesntFullfillEndEntityProfile 
	 * @throws ClassCastException 
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#genTokenCertificates(org.ejbca.core.protocol.ws.objects.UserDataVOWS, java.util.List, org.ejbca.core.protocol.ws.objects.HardTokenDataWS)
	 */
	
	public List<TokenCertificateResponseWS> genTokenCertificates(UserDataVOWS userDataWS, List<TokenCertificateRequestWS> tokenRequests, HardTokenDataWS hardTokenDataWS, boolean overwriteExistingSN) throws AuthorizationDeniedException, WaitingForApprovalException, HardTokenExistsException,UserDoesntFullfillEndEntityProfile, ApprovalException, EjbcaException {
		ArrayList<TokenCertificateResponseWS> retval = new ArrayList<TokenCertificateResponseWS>();

		Admin intAdmin = new Admin(Admin.TYPE_INTERNALUSER);
		boolean userExists = getUserAdminSession().existsUser(intAdmin, userDataWS.getUsername());	    
		Admin admin = null;
		int endEntityProfileId = 0;

		// Get Significant user Id
		CAInfo significantcAInfo = null;
		try {
			significantcAInfo = getCAAdminSession().getCAInfo(intAdmin, userDataWS.getCaName());
		} catch (Exception e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		}
		if(significantcAInfo == null){
			throw new EjbcaException("Error the given CA : " + userDataWS.getCaName() + " couldn't be found.");
		}

		try{
			if(isAdmin()){			
				admin = getAdmin();
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_CREATECERTIFICATE);
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.HARDTOKEN_ISSUEHARDTOKENS);
				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + significantcAInfo.getCAId());
				if(userExists){
					getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_EDITENDENTITY);
					UserDataVO userDataVO = getUserAdminSession().findUser(admin, userDataWS.getUsername());
					endEntityProfileId = userDataVO.getEndEntityProfileId();
					getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.EDIT_RIGHTS);
					if(overwriteExistingSN){
						getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_REVOKEENDENTITY);
						getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.REVOKE_RIGHTS);
					}
				}else{
					getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_CREATEENDENTITY);
					endEntityProfileId = getRAAdminSession().getEndEntityProfileId(admin, userDataWS.getEndEntityProfileName());	    	  
					if(endEntityProfileId == 0){
						throw new EjbcaException("Error given end entity profile : " + userDataWS.getEndEntityProfileName() +" couldn't be found");
					}
					getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.CREATE_RIGHTS);
					if(overwriteExistingSN){
						getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_REVOKEENDENTITY);
						getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + endEntityProfileId + AvailableAccessRules.REVOKE_RIGHTS);				       
					}
				}

			}else{
				// add approval
			}
		} catch(NamingException e){
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (FinderException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		}        

		ArrayList<java.security.cert.Certificate> genCertificates = new ArrayList<java.security.cert.Certificate>();
		if(getHardTokenSession().existsHardToken(admin, hardTokenDataWS.getHardTokenSN())){
			if(overwriteExistingSN){
				// fetch all old certificates and revoke them.
				Collection currentCertificates = getHardTokenSession().findCertificatesInHardToken(admin, hardTokenDataWS.getHardTokenSN());
				HardTokenData currentHardToken = getHardTokenSession().getHardToken(admin, hardTokenDataWS.getHardTokenSN(), false);
				Iterator iter = currentCertificates.iterator();
				while(iter.hasNext()){
					java.security.cert.X509Certificate nextCert = (java.security.cert.X509Certificate) iter.next();
					try {
						getUserAdminSession().revokeCert(admin, nextCert.getSerialNumber(), nextCert.getIssuerDN().toString(), currentHardToken.getUsername(), RevokedCertInfo.REVOKATION_REASON_SUPERSEDED);
					} catch (FinderException e) {
						throw new EjbcaException("Error revoking old certificate, the user : " + currentHardToken.getUsername() + " of the old certificate couldn't be found in database.");
					}
				}

			}else{
				throw new HardTokenExistsException("Error hard token with sn " + hardTokenDataWS.getHardTokenSN() + " already exists.");
			}

		}
		try{
			// Check if the userdata exist and edit/add it depending on which
			String password = PasswordGeneratorFactory.getInstance(PasswordGeneratorFactory.PASSWORDTYPE_ALLPRINTABLE).getNewPassword(8, 8);
			UserDataVO userData = convertUserDataVOWS(admin, userDataWS);
			userData.setPassword(password);
			if(userExists){
				getUserAdminSession().changeUser(admin, userData, true);
			}else{
				getUserAdminSession().addUser(admin, userData, true);
			}

			Date bDate = new Date(System.currentTimeMillis() - (10 * 60 * 1000));
			
			Iterator<TokenCertificateRequestWS> iter = tokenRequests.iterator();
			while(iter.hasNext()){
				TokenCertificateRequestWS next = iter.next();

				int certificateProfileId = getCertStoreSession().getCertificateProfileId(admin, next.getCertificateProfileName());
				if(certificateProfileId == 0){
					throw new EjbcaException("Error the given Certificate Profile : " + next.getCertificateProfileName() + " couldn't be found.");
				}
				
				Date eDate = null;
				
				if(next.getValidityIdDays() != null ){
					try{
						long validity = Long.parseLong(next.getValidityIdDays());
						eDate = new Date(System.currentTimeMillis() + (validity  * 3600 *24 * 1000));
					}catch (NumberFormatException e){
						throw new EjbcaException("Error : Validity in Days must be a number");
					}
				}
				
				CAInfo cAInfo = getCAAdminSession().getCAInfo(admin, next.getCAName());
				if(cAInfo == null){
					throw new EjbcaException("Error the given CA : " + next.getCAName() + " couldn't be found.");
				}

				getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + cAInfo.getCAId());
				if(next.getType() == HardTokenConstants.REQUESTTYPE_PKCS10_REQUEST){						
					userData.setCertificateProfileId(certificateProfileId);
					userData.setCAId(cAInfo.getCAId());
					userData.setPassword(password);
					userData.setStatus(UserDataConstants.STATUS_NEW);
					getUserAdminSession().changeUser(admin, userData, false);
					PKCS10RequestMessage pkcs10req = new PKCS10RequestMessage(next.getPkcs10Data());
					java.security.cert.Certificate cert;
					if(eDate == null){
					    cert =  getSignSession().createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey());
					}else{
						cert =  getSignSession().createCertificate(admin,userData.getUsername(),password, pkcs10req.getRequestPublicKey(), -1, bDate, eDate);
					}
					
					genCertificates.add(cert);
					retval.add(new TokenCertificateResponseWS(new Certificate(cert)));
				}else
					if(next.getType() == HardTokenConstants.REQUESTTYPE_KEYSTORE_REQUEST){

						if(!next.getTokenType().equals(HardTokenConstants.TOKENTYPE_PKCS12)){
							throw new EjbcaException("Unsupported Key Store Type : " + next.getTokenType() + " only " + HardTokenConstants.TOKENTYPE_PKCS12 + " is supported");
						}
						KeyPair keys = KeyTools.genKeys(next.getKeyspec(), next.getKeyalg());							  
						userData.setCertificateProfileId(certificateProfileId);
						userData.setCAId(cAInfo.getCAId());
						userData.setPassword(password);
						userData.setStatus(UserDataConstants.STATUS_NEW);
						getUserAdminSession().changeUser(admin, userData, true);
						X509Certificate cert;
						if(eDate == null){
						    cert =  (X509Certificate) getSignSession().createCertificate(admin,userData.getUsername(),password, keys.getPublic());
						}else{
							cert =  (X509Certificate) getSignSession().createCertificate(admin,userData.getUsername(),password, keys.getPublic(), -1, bDate, eDate);
						}
						
						genCertificates.add(cert);      
						// Generate Keystore
						// Fetch CA Cert Chain.	        
						Collection chain =  getCAAdminSession().getCAInfo(admin, cAInfo.getCAId()).getCertificateChain();
						String alias = CertTools.getPartFromDN(CertTools.getSubjectDN(cert), "CN");
						if (alias == null){
							alias = userData.getUsername();
						}	      	      
						java.security.KeyStore pkcs12 = KeyTools.createP12(alias, keys.getPrivate(), cert, chain);

						retval.add(new TokenCertificateResponseWS(new KeyStore(pkcs12, password)));
					}else{
						throw new EjbcaException("Error in request, only REQUESTTYPE_PKCS10_REQUEST and REQUESTTYPE_KEYSTORE_REQUEST are supported token requests.");
					}
			}

		}catch(CreateException e){
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (InvalidKeyException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (ObjectNotFoundException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (NoSuchProviderException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (KeyStoreException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CertificateException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (InvalidKeySpecException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (IOException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (InvalidAlgorithmParameterException e) {
			log.error("EJBCA WebService error, genTokenCertificates : ",e);
			throw new EjbcaException(e.getMessage());
		}finally{
			try {
				getUserAdminSession().setUserStatus(admin, userDataWS.getUsername(), UserDataConstants.STATUS_GENERATED);
			} catch (FinderException e) {
				log.error("EJBCA WebService error, genTokenCertificates : ",e);
				throw new EjbcaException(e.getMessage());
			}
		}

		// Add hard token data
		HardToken hardToken;
		String signatureInitialPIN = "";
		String signaturePUK = "";
		String basicInitialPIN = "";
		String basicPUK = "";
		Iterator<PINDataWS> iter = hardTokenDataWS.getPinDatas().iterator();
		while(iter.hasNext()){
			PINDataWS pinData = iter.next();
			switch(pinData.getType()){
			case HardTokenConstants.PINTYPE_BASIC :
				basicInitialPIN = pinData.getInitialPIN();
				basicPUK = pinData.getPUK(); 
				break;
			case HardTokenConstants.PINTYPE_SIGNATURE :
				signatureInitialPIN = pinData.getInitialPIN();
				signaturePUK = pinData.getPUK();
				break;
			default :
				throw new EjbcaException("Unsupported PIN Type " + pinData.getType());
			}
		}
		int tokenType = SwedishEIDHardToken.THIS_TOKENTYPE;
		switch (hardTokenDataWS.getTokenType()){
		case HardTokenConstants.TOKENTYPE_SWEDISHEID :
			hardToken = new SwedishEIDHardToken(basicInitialPIN,basicPUK,signatureInitialPIN,signaturePUK,0);	
			break;
		case HardTokenConstants.TOKENTYPE_ENHANCEDEID :
			hardToken = new EnhancedEIDHardToken(signatureInitialPIN,signaturePUK,basicInitialPIN,basicPUK,false,0);
			tokenType = EnhancedEIDHardToken.THIS_TOKENTYPE;
			break;
		default:
			throw new EjbcaException("Unsupported Token Type : " + hardTokenDataWS.getTokenType());

		}

		hardToken.setLabel(hardTokenDataWS.getLabel());	
		if(overwriteExistingSN){
			try {
				getHardTokenSession().removeHardToken(admin, hardTokenDataWS.getHardTokenSN());
			} catch (HardTokenDoesntExistsException e) {
				log.error("EJBCA WebService error, genTokenCertificates : ",e);
				throw new EjbcaException(e.getMessage());
			}
		}
		getHardTokenSession().addHardToken(admin, hardTokenDataWS.getHardTokenSN(), userDataWS.getUsername(), significantcAInfo.getSubjectDN(), tokenType, hardToken, genCertificates, hardTokenDataWS.getCopyOfSN());

		return retval; 	
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
		}
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenData(java.lang.String)
	 */
	public HardTokenDataWS getHardTokenData(String hardTokenSN, boolean viewPUKData, boolean onlyValidCertificates) throws AuthorizationDeniedException, HardTokenDoesntExistsException, EjbcaException{
		HardTokenDataWS retval = null;
		Admin admin = getAdmin();
		HardTokenData hardTokenData = getHardTokenSession().getHardToken(admin, hardTokenSN, viewPUKData);
		if(hardTokenData == null){
			throw new HardTokenDoesntExistsException("Error, hard token with SN " + hardTokenSN + " doesn't exist.");
		}
		isAuthorizedToHardTokenData(admin, hardTokenData.getUsername(), viewPUKData);
		Collection certs = getHardTokenSession().findCertificatesInHardToken(admin, hardTokenSN);
		
		if(onlyValidCertificates){
			try {
				certs = returnOnlyValidCertificates(admin, certs);
			} catch (ClassCastException e) {
				log.error("EJBCA WebService error, getHardTokenData : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (CreateException e) {
				log.error("EJBCA WebService error, getHardTokenData : ",e);
			    throw new EjbcaException(e.getMessage());
			} catch (NamingException e) {
				log.error("EJBCA WebService error, getHardTokenData : ",e);
			    throw new EjbcaException(e.getMessage());
			}
		}
		
		retval = convertHardTokenToWS(hardTokenData,certs,viewPUKData);			
		return retval;
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getHardTokenDatas(java.lang.String)
	 */
	public List<HardTokenDataWS> getHardTokenDatas(String username, boolean viewPUKData, boolean onlyValidCertificates) throws AuthorizationDeniedException, EjbcaException{
		List<HardTokenDataWS> retval = new  ArrayList<HardTokenDataWS>();
		Admin admin = getAdmin();		
		isAuthorizedToHardTokenData(admin, username, viewPUKData);

		Collection<?> hardtokens = getHardTokenSession().getHardTokens(admin, username, viewPUKData);
		Iterator iter = hardtokens.iterator();
		while(iter.hasNext()){
			HardTokenData next = (HardTokenData) iter.next();
			getAuthorizationSession().isAuthorizedNoLog(getAdmin(), AvailableAccessRules.CAPREFIX + next.getSignificantIssuerDN().hashCode());
			Collection certs = getHardTokenSession().findCertificatesInHardToken(admin, next.getTokenSN());
			if(onlyValidCertificates){
				try {
					certs = returnOnlyValidCertificates(admin, certs);
				} catch (ClassCastException e) {
					log.error("EJBCA WebService error, getHardTokenData : ",e);
				    throw new EjbcaException(e.getMessage());
				} catch (CreateException e) {
					log.error("EJBCA WebService error, getHardTokenData : ",e);
				    throw new EjbcaException(e.getMessage());
				} catch (NamingException e) {
					log.error("EJBCA WebService error, getHardTokenData : ",e);
				    throw new EjbcaException(e.getMessage());
				}
			}
			retval.add(convertHardTokenToWS(next,certs, viewPUKData));
		}
		
		return retval;
	}





	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#republishCertificate(java.lang.String, java.lang.String)
	 */
	public void republishCertificate(String serialNumberInHex,String issuerDN) throws AuthorizationDeniedException, PublisherException, EjbcaException{
		Admin admin = getAdmin();
		try{
			String bcIssuerDN = CertTools.stringToBCDNString(issuerDN);
			CertReqHistory certreqhist = getCertStoreSession().getCertReqHistory(admin,new BigInteger(serialNumberInHex,16), bcIssuerDN);
			if(certreqhist == null){
				throw new PublisherException("Error: the  certificate with  serialnumber : " + serialNumberInHex +" and issuerdn " + issuerDN + " couldn't be found in database.");
			}

			isAuthorizedToRepublish(admin, certreqhist.getUsername(),bcIssuerDN.hashCode());

			if(certreqhist != null){
				CertificateProfile certprofile = getCertStoreSession().getCertificateProfile(admin,certreqhist.getUserDataVO().getCertificateProfileId());
				java.security.cert.Certificate cert = getCertStoreSession().findCertificateByFingerprint(admin, certreqhist.getFingerprint());
				if(certprofile != null){
					CertificateInfo certinfo = getCertStoreSession().getCertificateInfo(admin, certreqhist.getFingerprint());
					if(certprofile.getPublisherList().size() > 0){
						if(getPublisherSession().storeCertificate(admin, certprofile.getPublisherList(), cert, certreqhist.getUserDataVO().getUsername(), certreqhist.getUserDataVO().getPassword(),
								certinfo.getCAFingerprint(), certinfo.getStatus() , certinfo.getType(), certinfo.getRevocationDate().getTime(), certinfo.getRevocationReason(), certreqhist.getUserDataVO().getExtendedinformation())){
						}else{
							throw new PublisherException("Error: publication failed to at least one of the defined publishers.");
						}
					}else{
						throw new PublisherException("Error no publisher defined for the given certificate.");
					}

				}else{
					throw new PublisherException("Error : Certificate profile couldn't be found for the given certificate.");
				}	  
			}
		} catch(NamingException e){
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, republishCertificate : ",e);
			throw new EjbcaException(e.getMessage());
		}
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#customLog(int, String, String)
	 */
	public void customLog(int level, String type, String cAName, String username, Certificate certificate, String msg) throws AuthorizationDeniedException, EjbcaException {
		Admin admin = getAdmin();
		
		try{
			int event = LogEntry.EVENT_ERROR_CUSTOMLOG;
			switch (level) {
			case IEjbcaWS.CUSTOMLOG_LEVEL_ERROR:
				break;
			case IEjbcaWS.CUSTOMLOG_LEVEL_INFO:
				event = LogEntry.EVENT_INFO_CUSTOMLOG;
				break;
			default:
				throw new EjbcaException("Illegal level "+ level + " sent to custonLog call.");			
			}

			java.security.cert.Certificate logCert = null;
			if(certificate != null){
				logCert = CertificateHelper.getCertificate(certificate.getCertificateData());
			}

			int caId = admin.getCaId();
			if(cAName  != null){
				CAInfo cAInfo = getCAAdminSession().getCAInfo(admin, cAName);
				if(cAInfo == null){
					throw new EjbcaException("Error given CA Name : " + cAName + " doesn't exists.");
				}
				caId = cAInfo.getCAId();
			}

			String comment = type + " : " + msg;
			getLogSession().log(admin, caId, LogEntry.MODULE_CUSTOM, new Date(), username, (X509Certificate) logCert, event, comment);
		} catch (CertificateException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, customLog : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#deleteUserDataFromSource(List, String, boolean)
	 */
	public boolean deleteUserDataFromSource(List<String> userDataSourceNames, String searchString, boolean removeMultipleMatch) throws AuthorizationDeniedException, MultipleMatchException, UserDataSourceException, EjbcaException {
		
		Admin admin = getAdmin();
		ArrayList<Integer> userDataSourceIds = new ArrayList<Integer>();
		Iterator<String> iter = userDataSourceNames.iterator();
		while(iter.hasNext()){
			String nextName = iter.next();
			int id = getUserDataSourceSession().getUserDataSourceId(admin, nextName);
			if(id == 0){
				throw new UserDataSourceException("Error: User Data Source with name : " + nextName + " couldn't be found, aborting operation.");
			}
			userDataSourceIds.add(new Integer(id));
		}
				
		return getUserDataSourceSession().removeUserData(admin, userDataSourceIds, searchString, removeMultipleMatch);
	}
	
	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#isApproved(int)
	 */
	public int isApproved(int approvalId) throws ApprovalException, EjbcaException, ApprovalRequestExpiredException{
		int retval = 0;
		
		try {
			retval = this.getApprovalSession().isApproved(getAdmin(true), approvalId);
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (AuthorizationDeniedException e) {
			log.error("EJBCA WebService error, isApproved : ",e);
		    throw new EjbcaException(e.getMessage());
		} 
		
		return retval;
	}

	/**
	 * @see org.ejbca.core.protocol.ws.common.IEjbcaWS#getCertificate(String, String)
	 */
	public Certificate getCertificate(String certSNinHex, String issuerDN) throws AuthorizationDeniedException, EjbcaException {
		Certificate retval = null;
		Admin admin = getAdmin(true);
		String bcString = CertTools.stringToBCDNString(issuerDN);
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWCERTIFICATE);
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + bcString.hashCode());
		
		try {
			java.security.cert.Certificate cert = getCertStoreSession().findCertificateByIssuerAndSerno(admin, issuerDN, new BigInteger(certSNinHex,16));
			if(cert != null){
				retval = new Certificate(cert);
			}
		} catch (ClassCastException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CreateException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (NamingException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		} catch (CertificateEncodingException e) {
			log.error("EJBCA WebService error, getCertificate : ",e);
		    throw new EjbcaException(e.getMessage());
		}
		
		return retval;
	}
	
	private Admin getAdmin() throws AuthorizationDeniedException, EjbcaException{		  
		  return getAdmin(false);
	}
	
	private Admin getAdmin(boolean allowNonAdmins) throws AuthorizationDeniedException, EjbcaException{
		Admin admin = null;
		try{
			MessageContext msgContext = wsContext.getMessageContext();
			HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
			X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

			if(certificates == null){
				throw new AuthorizationDeniedException("Error no client certificate recieved used for authentication.");
			}

			admin = new Admin(certificates[0]);
			// Check that user have the administrator flag set.
			if(!allowNonAdmins){
				getUserAdminSession().checkIfCertificateBelongToAdmin(admin, certificates[0].getSerialNumber(), certificates[0].getIssuerDN().toString());
				getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_ADMINISTRATOR);
			}

			RevokedCertInfo revokeResult =  getCertStoreSession().isRevoked(new Admin(Admin.TYPE_INTERNALUSER),CertTools.stringToBCDNString(certificates[0].getIssuerDN().toString()), certificates[0].getSerialNumber());
			if(revokeResult == null || revokeResult.getReason() != RevokedCertInfo.NOT_REVOKED){
				throw new AuthorizationDeniedException("Error administrator certificate doesn't exist or is revoked.");
			}

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

		return admin;
	}
	
	/**
	 * Method used to check if the admin is an administrator
	 * i.e have administrator flag set and access to resource
	 * /administrator
	 * @return
	 * @throws AuthorizationDeniedException 
	 */
	private boolean isAdmin() throws EjbcaException {
		boolean retval = false;
		MessageContext msgContext = wsContext.getMessageContext();
		HttpServletRequest request = (HttpServletRequest) msgContext.get(MessageContext.SERVLET_REQUEST);
		X509Certificate[] certificates = (X509Certificate[]) request.getAttribute("javax.servlet.request.X509Certificate");

		if(certificates == null){
			throw new EjbcaException("Error no client certificate recieved used for authentication.");
		}

		Admin admin = new Admin(certificates[0]);
		try{
			getUserAdminSession().checkIfCertificateBelongToAdmin(admin, certificates[0].getSerialNumber(), certificates[0].getIssuerDN().toString());
			getAuthorizationSession().isAuthorizedNoLog(admin,AvailableAccessRules.ROLE_ADMINISTRATOR);
			retval = true;
		}catch(AuthorizationDeniedException e){}
		
		
		return retval;
	}

	private void isAuthorizedToRepublish(Admin admin, String username, int caid) throws AuthorizationDeniedException, EjbcaException{
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWCERTIFICATE);
		UserDataVO userdata = null;
		try {
			userdata = getUserAdminSession().findUser(admin, username);
		} catch (FinderException e) {
			throw new EjbcaException("Error the  user doesn't seem to exist.");
		}
		if(userdata == null){
			throw new EjbcaException("Error the  user doesn't seem to exist.");
		}
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.VIEW_RIGHTS);
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.CAPREFIX + caid );		
        		
	}
	
	
	private void isAuthorizedToHardTokenData(Admin admin, String username, boolean viewPUKData) throws AuthorizationDeniedException, EjbcaException {
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWHARDTOKENS);
		UserDataVO userdata = null;
		boolean userExists = false;
		try {
			userdata = getUserAdminSession().findUser(admin, username);
			if(userdata != null){
				userExists = true;
			}
		} catch (FinderException e) {}
		
		getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWHARDTOKENS);
		if(viewPUKData){
			getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.REGULAR_VIEWPUKS);
		}
		
		
		
		if(userExists){		
		  getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.HARDTOKEN_RIGHTS);
		  if(viewPUKData){
			getAuthorizationSession().isAuthorizedNoLog(admin, AvailableAccessRules.ENDENTITYPROFILEPREFIX + userdata.getEndEntityProfileId() + AvailableAccessRules.HARDTOKEN_PUKDATA_RIGHTS);			
		  }
		}
		
		
		
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
	 * Method used to convert a HardToken data to a WS version
	 * @param data
	 * @throws EjbcaException 
	 */
	private HardTokenDataWS convertHardTokenToWS(HardTokenData data, Collection certificates, boolean includePUK) throws EjbcaException {
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

	
	private IUserDataSourceSessionLocal userdatasourcesession = null;
	private IUserDataSourceSessionLocal getUserDataSourceSession() {
		try{
			if(userdatasourcesession == null){
				Context context = new InitialContext();
				userdatasourcesession = ((IUserDataSourceSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"UserDataSourceSessionLocal"), IUserDataSourceSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing User Data Source Session Bean",e);
			throw new EJBException(e);
		}
		return userdatasourcesession;
	}

	
	private ILogSessionLocal logsession = null;
	private ILogSessionLocal getLogSession() {
		try{
			if(logsession == null){
				Context context = new InitialContext();
				logsession = ((ILogSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"LogSessionLocal"), ILogSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Log Session Bean",e);
			throw new EJBException(e);
		}
		return logsession;
	}
	
	private IPublisherSessionLocal publishersession = null;
	private IPublisherSessionLocal getPublisherSession() {
		try{
			if(publishersession == null){
				Context context = new InitialContext();
				publishersession = ((IPublisherSessionLocalHome) javax.rmi.PortableRemoteObject.narrow(context.lookup(
				"PublisherSessionLocal"), IPublisherSessionLocalHome.class)).create();   
			}
		}catch(Exception e)	{
			log.error("Error instancing Publisher Session Bean",e);
			throw new EJBException(e);
		}
		return publishersession;
	}




}
