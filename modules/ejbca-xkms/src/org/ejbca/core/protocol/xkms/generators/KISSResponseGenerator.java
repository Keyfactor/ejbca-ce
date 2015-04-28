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

package org.ejbca.core.protocol.xkms.generators;

import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.bind.JAXBElement;

import org.apache.log4j.Logger;
import org.cesecore.certificates.ca.CaSession;
import org.cesecore.certificates.certificate.CertificateInfo;
import org.cesecore.certificates.certificate.CertificateStoreSession;
import org.cesecore.certificates.crl.CrlStoreSession;
import org.cesecore.certificates.crl.RevokedCertInfo;
import org.cesecore.certificates.endentity.EndEntityInformation;
import org.cesecore.util.CertTools;
import org.ejbca.core.ejb.ra.EndEntityManagementSessionLocal;
import org.ejbca.core.model.InternalEjbcaResources;
import org.ejbca.core.model.authorization.AccessRulesConstants;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.UseKeyWithType;

/**
 * Class generating a response for a locate and validate calls
 * 
 *
 * @version $Id$
 */

public class KISSResponseGenerator extends RequestAbstractTypeResponseGenerator {
	
	 private static Logger log = Logger.getLogger(KISSResponseGenerator.class);
	
	 private static final InternalEjbcaResources intres = InternalEjbcaResources.getInstance();
	
	 private CertificateStoreSession certificateStoreSession;
	 private EndEntityManagementSessionLocal endEntityManagementSession;
	 
    public KISSResponseGenerator(String remoteIP, RequestAbstractType req, CertificateStoreSession certificateStoreSession, EndEntityManagementSessionLocal endEntityManagementSession, CrlStoreSession crlSession, CaSession caSession) {
        super(remoteIP, req, caSession, certificateStoreSession, crlSession);
        this.certificateStoreSession = certificateStoreSession;
        this.endEntityManagementSession = endEntityManagementSession;
    }

	/** 
	 * Method that should check the request and find 
	 * the appropriate certificates
	 * @param queryKeyBindingType
	 * @param name 
	 * @param result 
	 * @return A List of matching certificates
	 */
	protected List<X509Certificate> processRequest(QueryKeyBindingType queryKeyBindingType) {		
		ArrayList<X509Certificate> retval = new ArrayList<X509Certificate>();    

		int resSize = getResponseLimit() +1;

		if(queryKeyBindingType.getTimeInstant() != null){
			// TimeInstant in QueryKeyBinding not supported.
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_TIMEINSTANTNOTSUPPORTED;

			return retval;
		}

		// If keyInfo Exists
		if(queryKeyBindingType.getKeyInfo() != null){     		    		
			X509Certificate queryCert = null;
			// Only X509 Certificate and X509Chain is supported
			KeyInfoType keyInfoType = queryKeyBindingType.getKeyInfo();    
			
			
			if(keyInfoType.getContent().size() > 0 ){							
				@SuppressWarnings("unchecked")
                JAXBElement<X509DataType> x509DataType = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);

				Iterator<Object> iter = x509DataType.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
				while(iter.hasNext()){
					@SuppressWarnings("unchecked")
                    JAXBElement<byte[]> next =  (JAXBElement<byte[]>) iter.next();					
					if(next.getName().getLocalPart().equals("X509Certificate")){
						byte[] encoded = (byte[]) next.getValue();

						try {
							Certificate nextCert = CertTools.getCertfromByteArray(encoded);
							if (!CertTools.isCA(nextCert)) {
								queryCert = (X509Certificate)nextCert;								
							}
						} catch (CertificateException e) {
							log.error(intres.getLocalizedMessage("xkms.errordecodingcert"),e);
							resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
							resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
						}

					}else{
						resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
						resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
					}
				}

				if(queryCert != null && fulfillsKeyUsageAndUseKeyWith(queryKeyBindingType,queryCert)){
					retval.add(queryCert);    		    	
				}else{
					resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
					resultMinor = XKMSConstants.RESULTMINOR_NOMATCH;    		    	
				}    		        		   
			}else{
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;
			}
		}else{
			// Check that UseKeyWith isn't empty
			if(queryKeyBindingType.getUseKeyWith().size() >0){
				Query query = genQueryFromUseKeyWith(queryKeyBindingType.getUseKeyWith());
                
				try {            		
					Collection<EndEntityInformation> userDatas = endEntityManagementSession.query(pubAdmin, query, null, null, resSize, AccessRulesConstants.VIEW_END_ENTITY);
					if (log.isDebugEnabled()) {
						log.debug("endEntityManagementSession.query returned " + userDatas.size() + " results for query \"" + query.getQueryString() + "\"");
					}
					Iterator<EndEntityInformation> userIter = userDatas.iterator();
					while(userIter.hasNext() && retval.size() <= resSize){
						EndEntityInformation nextUser = userIter.next();
						// Find all the certificates of the matching users
						try {
							Collection<Certificate> userCerts = certificateStoreSession.findCertificatesByUsername(nextUser.getUsername());
							if (log.isDebugEnabled()) {
								log.debug("certificateStoreSession.findCertificatesByUsername " + userCerts.size() + " results for user \"" + nextUser.getUsername() + "\"");
							}
							// For all the certificates
							Iterator<Certificate> userCertIter = userCerts.iterator();
							while(userCertIter.hasNext() &&  retval.size() <= resSize){
								X509Certificate nextCert = (X509Certificate) userCertIter.next();            		        
								try {
									// Check that the certificate is valid 
									nextCert.checkValidity(new Date());								
									// and not revoked	
									CertificateInfo certInfo = certificateStoreSession.getCertificateInfo(CertTools.getFingerprintAsString(nextCert));
									if(certInfo.getRevocationReason() == RevokedCertInfo.NOT_REVOKED){
										if(fulfillsKeyUsageAndUseKeyWith(queryKeyBindingType,nextCert)){
											retval.add(nextCert);											
										}
									}
									if (log.isDebugEnabled()) {
										log.debug("certificateStoreSession.getCertificateInfo " + certInfo.getRevocationReason() + " results for fingerprint \"" + CertTools.getFingerprintAsString(nextCert) + "\"");
									}
								} catch (CertificateExpiredException e) {
								} catch (CertificateNotYetValidException e) {
								}											
							}						
						} catch (Exception e) {
							log.error(intres.getLocalizedMessage("xkms.errorcreatesession"),e);
							resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
							resultMinor = XKMSConstants.RESULTMINOR_FAILURE;						
						} 

					}

				} catch (IllegalQueryException e) {
					log.error(intres.getLocalizedMessage("xkms.illegaluserquery"),e);					
					resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
					resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
				}
			}else{
				resultMajor = XKMSConstants.RESULTMAJOR_SENDER;
				resultMinor = XKMSConstants.RESULTMINOR_MESSAGENOTSUPPORTED;         	
			}				

		}
		
		if(resultMajor == null){
		  if(retval.size() == getResponseLimit() + 1){
			retval.remove(retval.size() -1);
			resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
			resultMinor = XKMSConstants.RESULTMINOR_TOOMANYRESPONSES;
		  }
		
		  if(retval.size() == 0){
			resultMajor = XKMSConstants.RESULTMAJOR_SUCCESS;
			resultMinor = XKMSConstants.RESULTMINOR_NOMATCH;			
		  }
		}
		
		return retval;
	}

	private boolean fulfillsKeyUsageAndUseKeyWith(QueryKeyBindingType queryKeyBindingType, X509Certificate cert) {
		boolean retval = true;
		// Check that the certificate fullfills the key usage spec
		if(queryKeyBindingType.getKeyUsage().size() != 0){
			List<String> certKeyUsages = getCertKeyUsageSpec(cert);
			Iterator<String> iter = queryKeyBindingType.getKeyUsage().iterator();
			while(iter.hasNext()){
			  String next = iter.next();	
			  if(!certKeyUsages.contains(next)){
				  retval = false;
				  break;
			  }
			}
			

		}
		
		if(retval == true){
		  // Check that the certificate fullfills the usekeywith spec
			if(queryKeyBindingType.getUseKeyWith().size() != 0){
				try{
			      List<UseKeyWithType> certUseKeyWithList= genUseKeyWithAttributes(cert, queryKeyBindingType.getUseKeyWith());
			      if(certUseKeyWithList.size() == 0){
					  retval = false;			    	  
			      }
				}catch(Exception e){
					log.error(intres.getLocalizedMessage("xkms.errorextractingusekeywith"),e);					
	    			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
	    			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
				}
			}		  
		}
		
		return retval;
	}



    





	/**
	 * Method that checks that the given respondWith specification is valid.
	 * I.e contains one supported RespondWith tag.
	 */
	public boolean checkValidRespondWithRequest(List<String> respondWithList){
		boolean returnval = false;
		
		String[] supportedRespondWith = {XKMSConstants.RESPONDWITH_KEYNAME,
				                         XKMSConstants.RESPONDWITH_KEYVALUE,
				                         XKMSConstants.RESPONDWITH_X509CERT,
				                         XKMSConstants.RESPONDWITH_X509CHAIN,
				                         XKMSConstants.RESPONDWITH_X509CRL};		
	     
		for(int i=0;i<supportedRespondWith.length;i++){
		  returnval |= respondWithList.contains(supportedRespondWith[i]); 
		  if(returnval){
			  break;
		  }
		}
		  		
		return returnval;
	}


   
   protected Query genQueryFromUseKeyWith(List<UseKeyWithType> list){
	   Query retval = new Query(Query.TYPE_USERQUERY);
	   boolean retvalEmpty = true;
	   
	   Iterator<UseKeyWithType> iter = list.iterator();
	   while(iter.hasNext()){

		   if(!retvalEmpty){
			  retval.add(Query.CONNECTOR_OR);   
		   }
		   
		   UseKeyWithType useKeyWithType =  iter.next();
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMS)||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMSPROFILE) ||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLS)){
			    retval.add(UserMatch.MATCH_WITH_URI,UserMatch.MATCH_TYPE_BEGINSWITH,useKeyWithType.getIdentifier());
			    retvalEmpty=false;
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_SMIME)||
		  	  useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PGP)){
			   retval.add(UserMatch.MATCH_WITH_RFC822NAME,UserMatch.MATCH_TYPE_BEGINSWITH,useKeyWithType.getIdentifier());
			   retvalEmpty=false;
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSHTTP)){
			   retval.add(UserMatch.MATCH_WITH_COMMONNAME,UserMatch.MATCH_TYPE_BEGINSWITH,useKeyWithType.getIdentifier());
			   retvalEmpty=false;			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSSMTP)){
			   retval.add(UserMatch.MATCH_WITH_DNSNAME,UserMatch.MATCH_TYPE_BEGINSWITH,useKeyWithType.getIdentifier());
			   retvalEmpty=false;			   
		   }		   
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_IPSEC)){
			   retval.add(UserMatch.MATCH_WITH_IPADDRESS,UserMatch.MATCH_TYPE_BEGINSWITH,useKeyWithType.getIdentifier());
			   retvalEmpty=false;
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
			   retval.add(UserMatch.MATCH_WITH_DN,UserMatch.MATCH_TYPE_EQUALS,CertTools.stringToBCDNString(useKeyWithType.getIdentifier()));
			   retvalEmpty=false;
		   }
		   

	   }

	   return retval;
   }
   



}
