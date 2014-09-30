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

package org.ejbca.core.protocol.xkms.client;

import gnu.inet.encoding.StringprepException;

import java.net.MalformedURLException;
import java.net.URL;
import java.security.Key;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.ws.Dispatch;
import javax.xml.ws.Service;

import org.apache.log4j.Logger;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.TransformationException;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.xkms.XKMSService;
import org.ejbca.core.protocol.xkms.common.XKMSConstants;
import org.ejbca.core.protocol.xkms.common.XKMSUtil;
import org.w3._2002._03.xkms_.LocateRequestType;
import org.w3._2002._03.xkms_.LocateResultType;
import org.w3._2002._03.xkms_.MessageAbstractType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.RecoverRequestType;
import org.w3._2002._03.xkms_.RecoverResultType;
import org.w3._2002._03.xkms_.RegisterRequestType;
import org.w3._2002._03.xkms_.RegisterResultType;
import org.w3._2002._03.xkms_.ReissueRequestType;
import org.w3._2002._03.xkms_.ReissueResultType;
import org.w3._2002._03.xkms_.RequestAbstractType;
import org.w3._2002._03.xkms_.RevokeRequestType;
import org.w3._2002._03.xkms_.RevokeResultType;
import org.w3._2002._03.xkms_.ValidateRequestType;
import org.w3._2002._03.xkms_.ValidateResultType;
import org.w3c.dom.Document;

/**
 * Helper class that performs the prefix replacements
 * and does the dispatch invokation. 
 *
 * @version $Id$
 */

public class XKMSInvoker {

	private static Logger log = Logger.getLogger(XKMSInvoker.class);

	private static JAXBContext jAXBContext = null;
	private static Marshaller marshaller = null;
	private static Unmarshaller unmarshaller = null;
	private static DocumentBuilderFactory dbf = null;
	
	private Collection<Certificate> cacerts = null;

	private static Dispatch<Source> sourceDispatch = null; 
	private ObjectFactory xKMSObjectFactory = new ObjectFactory();	

	static{    	
		try {
			CryptoProviderTools.installBCProvider();
			org.apache.xml.security.Init.init();

			jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");    		
			marshaller = XKMSUtil.getNamespacePrefixMappedMarshaller(jAXBContext);
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			dbf.setExpandEntityReferences(false);
			unmarshaller = jAXBContext.createUnmarshaller();

		} catch (JAXBException e) {
			log.error("Error initializing RequestAbstractTypeResponseGenerator",e);
		}

	}
	    
	/**
	 * Creates an invoker to the web service at the specified URL
	 * 
	 * @param serviceURL the url to the web service.
	 * @param cacerts a collection of trusted CA signing responses. Use null if signed responses are not required.
	 */
	public XKMSInvoker(String serviceURL, Collection<Certificate> cacerts){
		XKMSService xkmsService;
		try {
			xkmsService = new XKMSService(new URL(serviceURL + "?wsdl"),new QName("http://www.w3.org/2002/03/xkms#wsdl", "XKMSService"));
			sourceDispatch = xkmsService.createDispatch(new QName("http://www.w3.org/2002/03/xkms#wsdl", "XKMSPort"), Source.class, Service.Mode.PAYLOAD);
		} catch (MalformedURLException e) {
		  log.error("Error creating XKMS Service instance",e);
		}   		
		this.cacerts = cacerts; // null if signed responses are not required.
	}

	/**
	 * Creates a locate call to the web service
	 * 
	 * @param locateRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @return a LocateResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 */
	public LocateResultType locate(LocateRequestType locateRequestType, X509Certificate signCert, Key privateKey) throws XKMSResponseSignatureException{
		JAXBElement<LocateRequestType> locateRequest = xKMSObjectFactory.createLocateRequest(locateRequestType);
		DOMSource domSource = performSigning(locateRequest, locateRequestType.getId(), signCert, privateKey);
		@SuppressWarnings("unchecked")
        JAXBElement<LocateResultType> response = (JAXBElement<LocateResultType>) invoke(domSource);
				
		return response.getValue();
	}
	
	/**
	 * Creates a validate call to the web service
	 * 
	 * @param validateRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @return a ValidateResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 */
	public ValidateResultType validate(ValidateRequestType validateRequestType, X509Certificate signCert, Key privateKey) throws XKMSResponseSignatureException{				
		JAXBElement<ValidateRequestType> validateRequest = xKMSObjectFactory.createValidateRequest(validateRequestType);
		DOMSource domSource = performSigning(validateRequest, validateRequestType.getId(), signCert, privateKey);
		@SuppressWarnings("unchecked")
        JAXBElement<ValidateResultType> response = (JAXBElement<ValidateResultType>) invoke(domSource);		
		
		return response.getValue();
	}
	
	/**
	 * Creates a register call to the web service
	 * 
	 * @param registerRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @param authenticationPassphrase the authenticationkeybinding passphrase, use null if it shouldn't be used.
	 * @param pOPPrivateKey private key to sign POP Element, use null to not append POPElement
	 * @param prototypeKeyBindingId is of the PrototypeKeyBinding tag.
	 * @return a RegisterResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 */
	public RegisterResultType register(RegisterRequestType registerRequestType, X509Certificate signCert, Key privateKey, String authenticationPassphrase, PrivateKey pOPPrivateKey, String prototypeKeyBindingId) throws XKMSResponseSignatureException, StringprepException{				
		JAXBElement<RegisterRequestType> registerRequest = xKMSObjectFactory.createRegisterRequest(registerRequestType);
		DOMSource domSource = performSigning(registerRequest, registerRequestType.getId(), signCert, privateKey, authenticationPassphrase, pOPPrivateKey, prototypeKeyBindingId);
		@SuppressWarnings("unchecked")
        JAXBElement<RegisterResultType> response = (JAXBElement<RegisterResultType>) invoke(domSource);		
		
		return response.getValue();
	}
	
	/**
	 * Creates a reissue call to the web service
	 * 
	 * @param reissueRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @param authenticationPassphrase the authenticationkeybinding passphrase, use null if it shouldn't be used.
	 * @param pOPPrivateKey private key to sign POP Element, use null to not append POPElement
	 * @param reissueKeyBindingId is of the PrototypeKeyBinding tag.
	 * @return a ReissueResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 */
	public ReissueResultType reissue(ReissueRequestType reissueRequestType, X509Certificate signCert, Key privateKey, String authenticationPassphrase, PrivateKey pOPPrivateKey, String reissueKeyBindingId) throws XKMSResponseSignatureException, StringprepException{				
		JAXBElement<ReissueRequestType> reissueRequest = xKMSObjectFactory.createReissueRequest(reissueRequestType);
		DOMSource domSource = performSigning(reissueRequest, reissueRequestType.getId(), signCert, privateKey, authenticationPassphrase, pOPPrivateKey, reissueKeyBindingId);
		@SuppressWarnings("unchecked")
        JAXBElement<ReissueResultType> response = (JAXBElement<ReissueResultType>) invoke(domSource);		
		
		return response.getValue();
	}
	
	/**
	 * Creates a recover call to the web service
	 * 
	 * @param recoverRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @param authenticationPassphrase the authenticationkeybinding passphrase, use null if it shouldn't be used.
	 * @param reissueKeyBindingId is of the PrototypeKeyBinding tag.
	 * @return a ReissueResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 */
	public RecoverResultType recover(RecoverRequestType recoverRequestType, X509Certificate signCert, Key privateKey, String authenticationPassphrase, String recoverKeyBindingId) throws XKMSResponseSignatureException, StringprepException{				
		JAXBElement<RecoverRequestType> recoverRequest = xKMSObjectFactory.createRecoverRequest(recoverRequestType);
		DOMSource domSource = performSigning(recoverRequest, recoverRequestType.getId(), signCert, privateKey, authenticationPassphrase, null, recoverKeyBindingId);
		@SuppressWarnings("unchecked")
        JAXBElement<RecoverResultType> response = (JAXBElement<RecoverResultType>) invoke(domSource);		
		
		return response.getValue();
	}
	
	/**
	 * Creates a revoke call to the web service
	 * 
	 * @param recvokeRequestType the request
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @param authenticationPassphrase the authenticationkeybinding passphrase, use null if it shouldn't be used.
	 * @param revokeKeyBindingId is of the PrototypeKeyBinding tag.
	 * @return a RevokeResultType
	 * @throws XKMSResponseSignatureException if the response signature didn't verify
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 */
	public RevokeResultType revoke(RevokeRequestType revokeRequestType, X509Certificate signCert, Key privateKey, String authenticationPassphrase, String revokeKeyBindingId) throws XKMSResponseSignatureException, StringprepException{				
		JAXBElement<RevokeRequestType> revokeRequest = xKMSObjectFactory.createRevokeRequest(revokeRequestType);
		DOMSource domSource = performSigning(revokeRequest, revokeRequestType.getId(), signCert, privateKey, authenticationPassphrase, null, revokeKeyBindingId);
		@SuppressWarnings("unchecked")
        JAXBElement<RevokeResultType> response = (JAXBElement<RevokeResultType>) invoke(domSource);		
		
		return response.getValue();
	}
	
	
	/**
	 * Method that performs the actual invokation.
	 * @param abstractMessageType
	 * @return
	 * @throws XKMSResponseSignatureException 
	 */
	@SuppressWarnings("unchecked")
    private JAXBElement<? extends MessageAbstractType> invoke(DOMSource domSource) throws XKMSResponseSignatureException{
		JAXBElement<? extends MessageAbstractType> result =null;
   
		try{						
			Source response = sourceDispatch.invoke(domSource);
			
			result = (JAXBElement<? extends MessageAbstractType>) unmarshaller.unmarshal(response);
			Document x = dbf.newDocumentBuilder().newDocument();
			marshaller.marshal(result, x);
			verifyResponseSignature(x);

			/*DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(((SAXSource) response).getInputSource());
			verifyResponseSignature(doc);
			result = (JAXBElement) unmarshaller.unmarshal(doc);*/
			
			
			//DocumentBuilder db = dbf.newDocumentBuilder();
			//Document doc = db.parse(((StreamSource) response).getInputStream());

			//verifyResponseSignature(doc);
			//result = (JAXBElement) unmarshaller.unmarshal(doc);
		} catch(JAXBException e){
			log.error("Error marshalling XKMS request",e);
		} catch (ParserConfigurationException e) {
			log.error("Error parsing XKMS response",e);
		/*} catch (SAXException e) {
			log.error("Error parsing XKMS response",e);
		} catch (IOException e) {
			log.error("Error parsing XKMS response",e);*/
		}
		
		return result;
	}
	
	
	/**
	 * Creates a signature on a request and returns a DOM source.
	 * 
	 * @param messageAbstractType the request to sign
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @return a DOMSource or null if request was invalid
	 */
	private DOMSource performSigning(JAXBElement<? extends MessageAbstractType> messageAbstractType, String messageId, X509Certificate signCert, Key privateKey){
		DOMSource retval = null;
		try{
			retval = performSigning(messageAbstractType, messageId, signCert, privateKey, null, null, null); 
		}catch(StringprepException e){
			// Should never happen
		}
		return retval;
	}
	
	/**
	 * Creates a signature on a request and returns a DOM source.
	 * 
	 * @param messageAbstractType the request to sign
	 * @param signCert the certificate that should sign the request, or null of no signing should be performed
	 * @param privateKey the key doing the signing, or null of no signing should be performed
	 * @param authenticationPassphrase the authenticationkeybinding passphrase, use null if it shouldn't be used.
	 * @param pOPPrivateKey private key to sign POP Element, use null to not append POPElement
	 * @param prototypeKeyBindingId is of the PrototypeKeyBinding tag.
	 * @return a DOMSource or null if request was invalid
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 */
	private DOMSource performSigning(JAXBElement<? extends MessageAbstractType> messageAbstractType, String messageId, X509Certificate signCert, Key privateKey, 
			                         String authenticationPassphrase, PrivateKey pOPPrivateKey, String prototypeKeyBindingId) throws StringprepException{
		    DOMSource retval = null;
		
			try{
				if(signCert != null && privateKey != null ){
					RequestAbstractType requestAbstractType = (RequestAbstractType) messageAbstractType.getValue();
					requestAbstractType.getResponseMechanism().add(XKMSConstants.RESPONSMEC_REQUESTSIGNATUREVALUE);
				}
				
				Document doc = dbf.newDocumentBuilder().newDocument();
				marshaller.marshal( messageAbstractType, doc );
				
				if(authenticationPassphrase != null){
					doc = XKMSUtil.appendKeyBindingAuthentication(doc, authenticationPassphrase, prototypeKeyBindingId);
				}
				
				if(pOPPrivateKey != null){
					doc = XKMSUtil.appendProofOfPossession(doc, pOPPrivateKey, prototypeKeyBindingId);
				}

				if(signCert != null && privateKey != null ){
					org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(doc, "", org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
					org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(doc);
					transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
					transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
					xmlSig.addDocument("#" + messageId, transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);        			
					xmlSig.addKeyInfo(signCert);
					doc.getDocumentElement().insertBefore( xmlSig.getElement() ,doc.getDocumentElement().getFirstChild());
					xmlSig.sign(privateKey);        
				}
				retval = new DOMSource(doc);
			}catch(XMLSignatureException e){
				log.error("Error performing XML Signature ",e);
			} catch (TransformationException e) {
				log.error("Error parsing XML request ",e);
			} catch (JAXBException e) {
				log.error("Error parsing XML request ",e);
			} catch (ParserConfigurationException e) {
				log.error("Error parsing XML request ",e);
			} catch (XMLSecurityException e) {
				log.error("Error performing XML Signature ",e);
			}						
		return retval;
	}
	
	/**
	 * Method that verifies the response signature,
	 * 
	 * doesn't check the revocation status of the server certificate.
	 * 
	 * @param response, the response from the service
	 * @throws {@link XKMSResponseSignatureException} if the signature doesn't verify
	 */
	private void verifyResponseSignature(Document doc) throws XKMSResponseSignatureException{
		try{
			/*if (log.isDebugEnabled()) {
		        ByteArrayOutputStream baos = new ByteArrayOutputStream();
		        XMLUtils.outputDOMc14nWithComments(doc, baos);
		        log.debug("verifyResponseSignature XMLUtils.outputDOMc14nWithComments: " + baos.toString());
			}*/
			
			boolean signatureExists = false;

			org.w3c.dom.NodeList xmlSigs = doc.getElementsByTagNameNS("http://www.w3.org/2000/09/xmldsig#", "Signature");
			signatureExists = xmlSigs.getLength() > 0;
		
			if(signatureExists && cacerts != null){
				try{																					
					org.w3c.dom.Element xmlSigElement = (org.w3c.dom.Element)xmlSigs.item(0);

					org.apache.xml.security.signature.XMLSignature xmlVerifySig = new org.apache.xml.security.signature.XMLSignature(xmlSigElement, null);

					org.apache.xml.security.keys.KeyInfo keyInfo = xmlVerifySig.getKeyInfo();
					java.security.cert.X509Certificate verCert = keyInfo.getX509Certificate();

					if (log.isDebugEnabled()) {
						log.debug("verCert SubjectDN:    " + CertTools.getSubjectDN(verCert));
						log.debug("verCert IssuerDN:     " + CertTools.getIssuerDN(verCert));
						log.debug("verCert NotAfter:     " + CertTools.getNotAfter(verCert));
						log.debug("verCert SerialNumber: " + CertTools.getSerialNumberAsString(verCert));

						byte[] signatureValue = xmlVerifySig.getSignatureValue();
						byte[] signatureContent = xmlVerifySig.getSignedInfo().getReferencedContentAfterTransformsItem(0).getBytes();
						MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
						messageDigest.update(signatureContent);
						byte[] digest = messageDigest.digest();
						log.debug("Signature length:    " + signatureValue.length);
						log.debug("Signature content:    " + new String(signatureContent));
						log.debug("Signature digest len:" + digest.length);
						log.debug("SignatureMethodURI:  " + xmlVerifySig.getSignedInfo().getSignatureMethodURI());
						Signature signer = Signature.getInstance("SHA1withRSA", "BC");
					    signer.initVerify(verCert.getPublicKey());
					    signer.update(digest);
						log.debug("Signature verifies?: " + signer.verify(signatureValue));
					}
					
					// Check signature
					if(xmlVerifySig.checkSignatureValue(verCert.getPublicKey())){ 							
						
						Collection<Certificate> cACertChain = cacerts;
						// Check issuer and validity						
						X509Certificate rootCert = null;
						Iterator<Certificate> iter = cACertChain.iterator();
						while(iter.hasNext()){
							X509Certificate cert = (X509Certificate) iter.next();
							if(cert.getIssuerDN().equals(cert.getSubjectDN())){
								rootCert = cert;
								break;
							}
						}

						if(rootCert == null){
							throw new CertPathValidatorException("Error Root CA cert not found in cACertChain"); 
						}

						List<Certificate> list = new ArrayList<Certificate>();
						list.add(verCert);
						list.addAll(cACertChain);

						CollectionCertStoreParameters ccsp = new CollectionCertStoreParameters(list);
						CertStore store = CertStore.getInstance("Collection", ccsp);

						//validating path
						List<Certificate> certchain = new ArrayList<Certificate>();
						certchain.addAll(cACertChain);
						certchain.add(verCert);
						CertPath cp = CertificateFactory.getInstance("X.509","BC").generateCertPath(certchain);

						Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
						trust.add(new TrustAnchor(rootCert, null));

						CertPathValidator cpv = CertPathValidator.getInstance("PKIX","BC");
						PKIXParameters param = new PKIXParameters(trust);
						param.addCertStore(store);
						param.setDate(new Date());				        	
						param.setRevocationEnabled(false);

						cpv.validate(cp, param); 
					}else{
						throw new XKMSResponseSignatureException("Error XKMS request signature doesn't verify.");						
					}
				}catch(Exception e){					
					throw new XKMSResponseSignatureException("Error when verifying signature request.",e);
				}
			}else{
				if(cacerts != null){
					throw new XKMSResponseSignatureException("Error XKMS response didn't return and signed response");
				}
			}
        } catch (TransformerFactoryConfigurationError e) {
			log.error("Error when DOM parsing request.",e);
		}
	}
}
