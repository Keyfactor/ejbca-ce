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

package org.ejbca.core.protocol.xkms.generators;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;

import javax.ejb.CreateException;
import javax.naming.NamingException;
import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.log4j.Logger;
import org.ejbca.core.model.ca.caadmin.CAInfo;
import org.ejbca.core.model.ca.certificateprofiles.CertificateProfile;
import org.ejbca.core.model.ca.crl.RevokedCertInfo;
import org.ejbca.core.model.ca.store.CertificateInfo;
import org.ejbca.core.model.ra.UserDataVO;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.util.CertTools;
import org.ejbca.util.dn.DNFieldExtractor;
import org.ejbca.util.query.IllegalQueryException;
import org.ejbca.util.query.Query;
import org.ejbca.util.query.UserMatch;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.KeyValueType;
import org.w3._2000._09.xmldsig_.RSAKeyValueType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2002._03.xkms_.KeyBindingAbstractType;
import org.w3._2002._03.xkms_.KeyBindingType;
import org.w3._2002._03.xkms_.QueryKeyBindingType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.StatusType;
import org.w3._2002._03.xkms_.UnverifiedKeyBindingType;
import org.w3._2002._03.xkms_.UseKeyWithType;
import org.w3._2002._03.xkms_.ValidityIntervalType;

/**
 * Class generating a response for a locate call
 * 
 * 
 * @author Philip Vendil 2006 sep 27
 *
 * @version $Id: KISSResponseGenerator.java,v 1.1 2006-12-22 09:21:39 herrvendil Exp $
 */

public class KISSResponseGenerator extends
		RequestAbstractTypeResponseGenerator {
	
	 private static Logger log = Logger.getLogger(KISSResponseGenerator.class);
	
	

	public KISSResponseGenerator(RequestAbstractType req) {
		super(req);
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
				JAXBElement<X509DataType> x509DataType = (JAXBElement<X509DataType>) keyInfoType.getContent().get(0);

				Iterator iter = x509DataType.getValue().getX509IssuerSerialOrX509SKIOrX509SubjectName().iterator();
				while(iter.hasNext()){
					JAXBElement next = (JAXBElement) iter.next();					
					if(next.getName().getLocalPart().equals("X509Certificate")){
						byte[] encoded = (byte[]) next.getValue();

						try {
							X509Certificate nextCert = CertTools.getCertfromByteArray(encoded);
							if(nextCert.getBasicConstraints() == -1){
								queryCert = nextCert;
							}
						} catch (CertificateException e) {
							log.error("Error decoding certificate");
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
					Collection userDatas = getUserAdminSession().query(intAdmin, query, null, null, resSize);

					Iterator<UserDataVO> userIter = userDatas.iterator();
					while(userIter.hasNext() && retval.size() <= resSize){
						UserDataVO nextUser = userIter.next();
						// Find all the certificates of the mathing users
						try {
							Collection userCerts = getCertStoreSession().findCertificatesByUsername(intAdmin, nextUser.getUsername());
							// For all the certificates
							Iterator<X509Certificate> userCertIter = userCerts.iterator();
							while(userCertIter.hasNext() &&  retval.size() <= resSize){
								X509Certificate nextCert = userCertIter.next();            		        
								try {
									// Check that the certificate is valid 
									nextCert.checkValidity(new Date());								
									// and not revoked	
									CertificateInfo certInfo = getCertStoreSession().getCertificateInfo(intAdmin, CertTools.getFingerprintAsString(nextCert));
									if(certInfo.getRevocationReason() == RevokedCertInfo.NOT_REVOKED){
										if(fulfillsKeyUsageAndUseKeyWith(queryKeyBindingType,nextCert)){
											retval.add(nextCert);											
										}
									}
								} catch (CertificateExpiredException e) {
								} catch (CertificateNotYetValidException e) {
								}											
							}						
						} catch (Exception e) {
							log.error("Error creating session beans.",e);
							resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
							resultMinor = XKMSConstants.RESULTMINOR_FAILURE;						
						} 

					}

				} catch (IllegalQueryException e) {
					log.error("Illegal User Query");
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
					log.error("Error extracting UseKeyWith Attributes from Cert");
	    			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
	    			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
				}
			}		  
		}
		
		return retval;
	}


	/**
     * Method adding supported response values specified
     * in the request
     * 
     * @param certificate to respond
     */
    protected KeyBindingAbstractType getResponseValues(QueryKeyBindingType queryKeyBindingType, X509Certificate cert, boolean validateReq){
    	UnverifiedKeyBindingType retval = xkmsFactory.createUnverifiedKeyBindingType();    	
    	if(validateReq){
    		retval = xkmsFactory.createKeyBindingType();
    		
    		((KeyBindingType) retval).setStatus(getStatus(cert));
    	}
    	    	

    	retval.setId(cert.getSerialNumber().toString(16));             
    	retval.setValidityInterval(getValidityInterval(cert));

    	KeyInfoType keyInfoType = sigFactory.createKeyInfoType();

    	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_KEYNAME)){
    		String keyName = cert.getSubjectDN().toString();
    		keyInfoType.getContent().add(sigFactory.createKeyName(keyName));    		    		    	  	
    	}

    	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_KEYVALUE)){
    		if(cert.getPublicKey() instanceof RSAPublicKey){  
    			RSAPublicKey pubKey = (RSAPublicKey) cert.getPublicKey();      	
    			RSAKeyValueType rSAKeyValueType = sigFactory.createRSAKeyValueType();
    			rSAKeyValueType.setModulus(pubKey.getModulus().toByteArray());
    			rSAKeyValueType.setExponent(pubKey.getPublicExponent().toByteArray());
    			KeyValueType keyValue = sigFactory.createKeyValueType();
    			keyValue.getContent().add(sigFactory.createRSAKeyValue(rSAKeyValueType));
    			keyInfoType.getContent().add(sigFactory.createKeyValue(keyValue));    		    		    	  	
    		}else{
    			log.error("Only RSA keys are supported for key value info.");
    			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
    			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
    		}
    	}

    	if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CERT) || 
    			req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN) ||
    			req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CRL)){
    		    X509DataType x509DataType = sigFactory.createX509DataType();
    		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CERT) && !req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN)){
    			try {    					
    				x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
    			} catch (CertificateEncodingException e) {
    				log.error("Error decoding certificate",e);
    				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
    				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
    			}
    		}
    		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CHAIN)){
    			int caid = CertTools.getIssuerDN(cert).hashCode();
    			try {
    				Iterator iter = getCAAdminSession().getCAInfo(intAdmin, caid).getCertificateChain().iterator();
    				while(iter.hasNext()){
    					X509Certificate next = (X509Certificate) iter.next();
    					x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(next.getEncoded()));
    				}
    				x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509Certificate(cert.getEncoded()));
    			} catch (Exception e) {
    				log.error("Error fetching last CRL",e);
    				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
    				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
    			}
    		}
    		if(req.getRespondWith().contains(XKMSConstants.RESPONDWITH_X509CRL)){
    			byte[] crl = null;
    			try {
    				crl = getCertStoreSession().getLastCRL(intAdmin, CertTools.getIssuerDN(cert));
    			} catch (Exception e) {
    				log.error("Error fetching last CRL",e);
    				resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
    				resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
    			}
    			x509DataType.getX509IssuerSerialOrX509SKIOrX509SubjectName().add(sigFactory.createX509DataTypeX509CRL(crl));
    		}    		
    		keyInfoType.getContent().add(sigFactory.createX509Data(x509DataType));
    		
    	}
    	retval.setKeyInfo(keyInfoType);
    	retval.getKeyUsage().addAll(getCertKeyUsageSpec(cert));
		try {
			retval.getUseKeyWith().addAll(genUseKeyWithAttributes(cert, queryKeyBindingType.getUseKeyWith()));
		} catch (Exception e) {
			log.error("Error extracting use key with attributes from cert",e);
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
			
		}
    	
    	
    	return retval;
    }
    
    /**
     * Method that checks the status of the certificate used
     * in a XKMS validate call. 
     * 
     * @param type
     * @param cert
     */
    private StatusType getStatus(X509Certificate cert) {
        StatusType retval = xkmsFactory.createStatusType();
        
        boolean allValid = true;
        boolean inValidSet = false;
        
        //Check validity
        try{
        	cert.checkValidity( new Date());
        	retval.getValidReason().add(XKMSConstants.STATUSREASON_VALIDITYINTERVAL);
        }catch(Exception e){
        	retval.getInvalidReason().add(XKMSConstants.STATUSREASON_VALIDITYINTERVAL);
        	allValid = false;
        	inValidSet = true;
        }
        
        // Check Issuer Trust
        try{
          int caid = CertTools.getIssuerDN(cert).hashCode();
		  CAInfo cAInfo = getCAAdminSession().getCAInfo(intAdmin, caid);
		  if(cAInfo != null){
			retval.getValidReason().add(XKMSConstants.STATUSREASON_ISSUERTRUST);
			
			// Check signature	
			try{
	          if(CertTools.verify(cert, cAInfo.getCertificateChain())){
	        	retval.getValidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
	          }else{
	        	retval.getInvalidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
	        	allValid = false;
	        	inValidSet = true;
	          }
			}catch(Exception e){
	        	retval.getInvalidReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
	        	allValid = false;	
	        	inValidSet = true;
			}
		  }else{
        	 retval.getInvalidReason().add(XKMSConstants.STATUSREASON_ISSUERTRUST);
        	 retval.getIndeterminateReason().add(XKMSConstants.STATUSREASON_SIGNATURE);
        	 allValid = false;
        	 inValidSet = true;
		  }
		  
          // Check RevokationReason
		  CertificateInfo certInfo = getCertStoreSession().getCertificateInfo(intAdmin, CertTools.getFingerprintAsString(cert));
		  if(certInfo != null){
			  if(certInfo.getRevocationReason() == RevokedCertInfo.NOT_REVOKED){
				  retval.getValidReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);				  
			  }else{
				  retval.getInvalidReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);
				  allValid = false;
				  inValidSet = true;
			  }			  			
		  }else{
			  retval.getIndeterminateReason().add(XKMSConstants.STATUSREASON_REVOCATIONSTATUS);
			  allValid = false;
		  }
		  
		  
        }catch(CreateException e){
        	log.error("Error creating SessionBean",e);
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
        } catch (ClassCastException e) {
        	log.error("Error creating SessionBean",e);
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
		} catch (NamingException e) {
			log.error("Error creating SessionBean",e);
			resultMajor = XKMSConstants.RESULTMAJOR_RECIEVER;
			resultMinor = XKMSConstants.RESULTMINOR_FAILURE;
		}
		
         if(allValid){
        	 retval.setStatusValue(XKMSConstants.STATUSVALUE_VALID);
         }else{
        	 if(inValidSet){
        		 retval.setStatusValue(XKMSConstants.STATUSVALUE_INVALID); 
        	 }else{
        		 retval.setStatusValue(XKMSConstants.STATUSVALUE_INDETERMINATE);
        	 }
         }
        
        
		return retval;
	}


	private ValidityIntervalType getValidityInterval(X509Certificate cert) {
    	ValidityIntervalType valitityIntervalType = xkmsFactory.createValidityIntervalType();
		try {    	
		  GregorianCalendar notBeforeGregorianCalendar = new GregorianCalendar();
		  notBeforeGregorianCalendar.setTime(cert.getNotBefore());
    	  XMLGregorianCalendar notBeforeXMLGregorianCalendar = javax.xml.datatype.DatatypeFactory.newInstance().newXMLGregorianCalendar(notBeforeGregorianCalendar);
    	  notBeforeXMLGregorianCalendar.normalize();
    	  valitityIntervalType.setNotBefore(notBeforeXMLGregorianCalendar);
    	
		  GregorianCalendar notAfterGregorianCalendar = new GregorianCalendar();
		  notAfterGregorianCalendar.setTime(cert.getNotAfter());
    	  XMLGregorianCalendar notAfterXMLGregorianCalendar = javax.xml.datatype.DatatypeFactory.newInstance().newXMLGregorianCalendar(notAfterGregorianCalendar);
    	  notAfterXMLGregorianCalendar.normalize();
    	  valitityIntervalType.setNotOnOrAfter(notAfterXMLGregorianCalendar);    	
    	
		} catch (DatatypeConfigurationException e) {
			log.error("Error setting Validity Interval", e);
		}  	
    	
    	
		return valitityIntervalType;
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

	/**
     * Method that returns the XKMS KeyUsage Constants that can be applied to the given 
     * X509Certiifcate
     * 
     * return List<String> of size 0 to 3 of XKMSConstants.KEYUSAGE_ constants.
     */
   protected List<String> getCertKeyUsageSpec(X509Certificate cert) {
	   ArrayList<String> retval = new ArrayList<String>();
	   
	   if(cert.getKeyUsage()[CertificateProfile.DATAENCIPHERMENT]){
		   retval.add(XKMSConstants.KEYUSAGE_ENCRYPTION);
	   }
	   if(cert.getKeyUsage()[CertificateProfile.DIGITALSIGNATURE] 
	      || cert.getKeyUsage()[CertificateProfile.KEYENCIPHERMENT]){
		   retval.add(XKMSConstants.KEYUSAGE_EXCHANGE);
	   }
	   if(XKMSConfig.signatureIsNonRep()){
		   if(cert.getKeyUsage()[CertificateProfile.NONREPUDIATION]){
			   retval.add(XKMSConstants.KEYUSAGE_SIGNATURE);
		   }
	   }else{
		     if(cert.getKeyUsage()[CertificateProfile.DIGITALSIGNATURE]){
		    	 retval.add(XKMSConstants.KEYUSAGE_SIGNATURE);
		     }		   
	   }
	   	   
	   return retval;
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
   
   /**
    * Method that determines the UseKeyWith attribute from an X509Certificate
    * and the requested UseKeyWithAttributes
    */
   protected List<UseKeyWithType> genUseKeyWithAttributes(X509Certificate cert, List<UseKeyWithType> reqUsages) throws Exception{
	   ArrayList<UseKeyWithType> retval = new ArrayList();
	   
	   Iterator<UseKeyWithType> iter = reqUsages.iterator();
	   while(iter.hasNext()){
		   UseKeyWithType useKeyWithType =  iter.next();
		   DNFieldExtractor altNameExtractor = new DNFieldExtractor(CertTools.getSubjectAlternativeName(cert),DNFieldExtractor.TYPE_SUBJECTALTNAME);
		   String cn = CertTools.getPartFromDN(cert.getSubjectDN().toString(), "CN");
		   
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMS)||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_XKMSPROFILE) ||
  		      useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLS)){
			    if(altNameExtractor.getField(DNFieldExtractor.URI, 0).startsWith(useKeyWithType.getIdentifier())){
			      retval.add(useKeyWithType);
			    }
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_SMIME)||
		  	  useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PGP)){
			    if(altNameExtractor.getField(DNFieldExtractor.RFC822NAME, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSHTTP)){
			    if(cn.startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   			   			   			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_TLSSMTP)){
			    if(altNameExtractor.getField(DNFieldExtractor.DNSNAME, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_IPSEC)){
			    if(altNameExtractor.getField(DNFieldExtractor.IPADDRESS, 0).startsWith(useKeyWithType.getIdentifier())){
				      retval.add(useKeyWithType);
				}			   
		   }
		   if(useKeyWithType.getApplication().equals(XKMSConstants.USEKEYWITH_PKIX)){
			    if(cert.getSubjectDN().toString().equalsIgnoreCase(CertTools.stringToBCDNString(useKeyWithType.getIdentifier()))){
				      retval.add(useKeyWithType);
				}			   
		   } 
	   }
	   
	
	   return retval;
   }


}
