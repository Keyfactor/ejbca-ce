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

package org.ejbca.core.protocol.xkms.common;

import gnu.inet.encoding.Stringprep;
import gnu.inet.encoding.StringprepException;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.PropertyException;
import javax.xml.bind.Unmarshaller;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.log4j.Logger;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.EncryptionConstants;
import org.cesecore.util.CryptoProviderTools;
import org.w3._2001._04.xmlenc_.EncryptedDataType;
import org.w3._2002._03.xkms_.ObjectFactory;
import org.w3._2002._03.xkms_.PrivateKeyType;
import org.w3._2002._03.xkms_.RSAKeyPairType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A util class containing static help methods to process various 
 * XKMS messages
 * 
 * 
 * @author Philip Vendil 2006 dec 30
 *
 * @version $Id$
 */

public class XKMSUtil {
	
	/** HMAC-SHA1 initial key values */
	public static final byte[] KEY_AUTHENTICATION = {0x1};
	public static final byte[] KEY_REVOCATIONCODEIDENTIFIER_PASS1 = {0x2};
	public static final byte[] KEY_REVOCATIONCODEIDENTIFIER_PASS2 = {0x3};
	public static final byte[] KEY_PRIVATEKEYDATA = {0x4};
	
	private static final String ENCRYPTION_ALGORITHMURI = XMLCipher.TRIPLEDES;
	private static final String SHAREDSECRET_HASH_ALGORITH = "http://www.w3.org/2000/09/xmldsig#hmac-sha1";
	
	private static Logger log = Logger.getLogger(XKMSUtil.class);
	
	private static ObjectFactory xKMSObjectFactory = new ObjectFactory();
	
	private static JAXBContext jAXBContext = null;
	private static Marshaller marshaller = null;
	private static Unmarshaller unmarshaller = null;
	private static DocumentBuilderFactory dbf = null;
	
	static{  
		try {
			CryptoProviderTools.installBCProviderIfNotAvailable();
			org.apache.xml.security.Init.init();
			
			jAXBContext = JAXBContext.newInstance("org.w3._2002._03.xkms_:org.w3._2001._04.xmlenc_:org.w3._2000._09.xmldsig_");
			marshaller = getNamespacePrefixMappedMarshaller(jAXBContext); 
			dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			unmarshaller = jAXBContext.createUnmarshaller();

		} catch (JAXBException e) {
			log.error("Error initializing RequestAbstractTypeResponseGenerator",e);
		}
	}
	
	/** We use our own NamespacePrefixMapper. There are different implementations of this however, and java switched in 
	 * jdk 1.6u18, but you can still stumble upon RI implementations which is why we have to do a bit of testing in this method.
	 * This depends on the jar jaxb-NamespacePrefixMapper-interfaces-2.0.0.jar when compiling since we need both:
	 * com.sun.xml.internal.bind.namespacePrefixMapper and com.sun.xml.bind.namespacePrefixMapper in order to compile.
	 * 
	 * See: http://pragmaticintegration.blogspot.com/2007/11/moving-jaxb-20-applications-built-by.html
	 * 
	 * @param jAXBContext
	 * @return Marshaller
	 * @throws JAXBException
	 */
	public static Marshaller getNamespacePrefixMappedMarshaller(JAXBContext jAXBContext) throws JAXBException {
		Marshaller marshaller = jAXBContext.createMarshaller();
		try {
			try {
				// Use JAXB distributed in Java 6 - note 'internal' 
				Object o = Class.forName("org.ejbca.core.protocol.xkms.common.XKMSNamespacePrefixMapper").newInstance();
				marshaller.setProperty("com.sun.xml.internal.bind.namespacePrefixMapper", o);				
				if (log.isDebugEnabled()) {
					log.debug("XKMS Marshaller: using com.sun.xml.internal.bind.namespacePrefixMapper (JAXB in Java6?)");					
				}
			} catch (PropertyException e) {
			    try {
			        // Reference implementation appears to be present (in endorsed dir?)
			        // Check if com.sun.xml.bind.marshaller.NamespacePrefixMapper exists, if not we are probably running JDK 7
			        Class.forName("com.sun.xml.bind.marshaller.NamespacePrefixMapper");
			        // No ClassNotFoundException, carry on and try to use the JAXB RA namespacePrefixMapper
			        Object o = Class.forName("org.ejbca.core.protocol.xkms.common.XKMSNamespacePrefixMapperRI").newInstance();
			        marshaller.setProperty("com.sun.xml.bind.namespacePrefixMapper", o);
			        if (log.isDebugEnabled()) {
			            log.debug("XKMS Marshaller: using com.sun.xml.bind.namespacePrefixMapper (JAXB RI?)");					
			        }
			    } catch (ClassNotFoundException ce) {
			        // With JDK 7 it seems to be enough with the org.ejbca.core.protocol.xkms.package-info.java
                    if (log.isDebugEnabled()) {
                        log.debug("XKMS Marshaller: not using any namespacePrefixMappper (JDK7?)");                   
                    }			        
			    }
			}
		} catch( PropertyException e ) {
			log.error("Error registering new namespace mapper property.",e);
		} catch (InstantiationException e) {
			log.error("Error instantiating new namespace mapper object.",e);
		} catch (IllegalAccessException e) {
			log.error("Error instantiating new namespace mapper object.",e);
		} catch (ClassNotFoundException e) {
			log.error("Error instantiating new namespace mapper object.",e);
		} catch (NoClassDefFoundError e) {
			log.error("Error instantiating old namespace mapper object.",e);
		}
		return marshaller;
	}

	/**
	 * Encrypting a java RSA Private key into a PrivateKeyType object used in register,reissue and recover respolses.
	 * using the shared secret.
	 * 
	 * The method uses the HMAC-SHA1 for generating the shared secret
	 * and tripple des for encryption
	 *
	 * @param rSAPrivateKey the privatekey
	 * @param sharedSecret the shared secret, cannot be null.
	 * @return The Document with the encrypted key included.
	 * @throws StringprepException if the shared secret doesn't conform with the SASLprep profile as specified in the XKMS specification.
	 * @throws XMLEncryptionException if any other exception occurs during the processing.
	 */
	public static PrivateKeyType getEncryptedXMLFromPrivateKey(RSAPrivateCrtKey rSAPrivateKey, String sharedSecret) throws StringprepException, XMLEncryptionException{
		PrivateKeyType privateKeyType = null;
		try{
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document rSAKeyPairDoc = db.newDocument();

        SecretKey sk = getSecretKeyFromPassphrase(sharedSecret,true, 24, KEY_PRIVATEKEYDATA);
        
        RSAKeyPairType rSAKeyPairType = xKMSObjectFactory.createRSAKeyPairType();
       
        rSAKeyPairType.setModulus(rSAPrivateKey.getModulus().toByteArray());
        rSAKeyPairType.setExponent(rSAPrivateKey.getPublicExponent().toByteArray());
        rSAKeyPairType.setP(rSAPrivateKey.getPrimeP().toByteArray());
        rSAKeyPairType.setQ(rSAPrivateKey.getPrimeQ().toByteArray());
        rSAKeyPairType.setDP(rSAPrivateKey.getPrimeExponentP().toByteArray());
        rSAKeyPairType.setDQ(rSAPrivateKey.getPrimeExponentQ().toByteArray()); 
        rSAKeyPairType.setInverseQ(rSAPrivateKey.getCrtCoefficient().toByteArray());
        rSAKeyPairType.setD(rSAPrivateKey.getPrivateExponent().toByteArray());

        JAXBElement<RSAKeyPairType> rSAKeyPair = xKMSObjectFactory.createRSAKeyPair(rSAKeyPairType);

		marshaller.marshal( rSAKeyPair, rSAKeyPairDoc );

		Document envelopedDoc = db.newDocument();
		Element unencryptedElement = envelopedDoc.createElement("PrivateKey");
		envelopedDoc.appendChild(unencryptedElement);
		Element node = (Element) envelopedDoc.adoptNode(rSAKeyPairDoc.getDocumentElement());
		unencryptedElement.appendChild(node);
		
        Element rootElement = envelopedDoc.getDocumentElement();
       
        
        XMLCipher xmlCipher =
            XMLCipher.getProviderInstance(ENCRYPTION_ALGORITHMURI,"BC");
        xmlCipher.init(XMLCipher.ENCRYPT_MODE, sk);

        EncryptedData encryptedData = xmlCipher.getEncryptedData();
        encryptedData.setMimeType("text/xml");
        
        xmlCipher.doFinal(envelopedDoc,rootElement,true);      

        @SuppressWarnings("unchecked")
        JAXBElement<EncryptedDataType> unmarshalledData = (JAXBElement<EncryptedDataType>) unmarshaller.unmarshal(envelopedDoc.getDocumentElement().getFirstChild());
        
        EncryptedDataType encryptedDataType = (EncryptedDataType) unmarshalledData.getValue();
        privateKeyType = xKMSObjectFactory.createPrivateKeyType();
        privateKeyType.setEncryptedData(encryptedDataType);
        
		} catch (ParserConfigurationException e) {
			log.error("Error encryption private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (XMLSecurityException e) {
			log.error("Error encryption private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);	
		} catch (JAXBException e) {
			log.error("Error encryption private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);	
		} catch (Exception e) {
			log.error("Error encryption private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);	
		}           
		
		return privateKeyType; 
	}
	
	/**
	 * Method to get the private key from an XKMS message with an encrypted
	 * PrivateKey tag. The method uses the HMAC-SHA1 for generating the shared secret
	 * and tripple des for encryption.
	 * 
	 * @param privateKeyType the JAXB version of the PrivateKey tag
	 * @param sharedSecret the shared secret, cannot be null.
	 * @return a java RSAPrivateKey 
	 * @throws StringprepException if the shared secret doesn't conform with the SASLprep profile as specified in the XKMS specification.
	 * @throws XMLEncryptionException if any other exception occurs during the processing.
	 */
	public static RSAPrivateKey getPrivateKeyFromEncryptedXML(PrivateKeyType privateKeyType, String sharedSecret) throws StringprepException, XMLEncryptionException{
		RSAPrivateKey privkey2 = null;
		try{
		DocumentBuilder db = dbf.newDocumentBuilder();
        Document privateKeyDoc = db.newDocument();
        marshaller.marshal(privateKeyType, privateKeyDoc);
        
        Element encryptedDataElement =
            (Element) privateKeyDoc.getElementsByTagNameNS(
                EncryptionConstants.EncryptionSpecNS,
                EncryptionConstants._TAG_ENCRYPTEDDATA).item(0);

        SecretKey sk = getSecretKeyFromPassphrase(sharedSecret,true, 24, KEY_PRIVATEKEYDATA);
                        
        XMLCipher xmlDecipher = XMLCipher.getProviderInstance(ENCRYPTION_ALGORITHMURI,"BC");
        
        xmlDecipher.init(XMLCipher.DECRYPT_MODE, sk);
       
        xmlDecipher.doFinal(privateKeyDoc, encryptedDataElement);
        
        @SuppressWarnings("unchecked")
        JAXBElement<RSAKeyPairType> rSAKeyPair = (JAXBElement<RSAKeyPairType>) unmarshaller.unmarshal(privateKeyDoc.getDocumentElement().getFirstChild());
        
        RSAKeyPairType rSAKeyPairType = rSAKeyPair.getValue();
        
                
        RSAPrivateCrtKeySpec rSAPrivateKeySpec = new RSAPrivateCrtKeySpec(new BigInteger(rSAKeyPairType.getModulus()), new BigInteger(rSAKeyPairType.getExponent()), 
        		             new BigInteger(rSAKeyPairType.getD()), new BigInteger(rSAKeyPairType.getP()), 
        		             new BigInteger(rSAKeyPairType.getQ()), new BigInteger(rSAKeyPairType.getDP()),
        		             new BigInteger(rSAKeyPairType.getDQ()), new BigInteger(rSAKeyPairType.getInverseQ())); 
        
        privkey2 = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(rSAPrivateKeySpec);
        
		} catch (InvalidKeySpecException e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (XMLSecurityException e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (JAXBException e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (ParserConfigurationException e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (Exception e) {
			log.error("Error decrypting private key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		}
		
		return privkey2;
	}
	
	/**
	 * Genereates a secret key from a passphrase according to the 
	 * XKMS specifikation. The HMAC-SHA1 algorithm is used.
	 * 
	 * The passphrase is first checked against SALSPrep profile
	 * according to the XKMS specificatiom 
	 * 
	 * @param passphrase the passphrase to use, may no be null
	 * @param performSASLprep if sASLprep should be called on the input string.
	 * @param keylength the length of the key returned.
	 * @param keyType one of the initial KEY_ constants
	 * @return The SecretKey used in encryption/decryption
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 * @throws XMLEncryptionException If any other exception occured during generation.
	 */
	public static SecretKey getSecretKeyFromPassphrase(String passphrase, boolean performSASLprep, int keylength, byte[] keyType) throws  StringprepException, XMLEncryptionException{
		SecretKey retval = null;
		try{
		byte[] finalKey = new byte[keylength];
		
		int keyIndex = 0;		
		byte[] currentKey = keyType;
       

		Document doc = dbf.newDocumentBuilder().newDocument();        
        SignatureAlgorithm sa = new SignatureAlgorithm(doc,
        		SHAREDSECRET_HASH_ALGORITH,
                33);
        
        // Make the string saslpreped
        String sASLPrepedPassword = passphrase;
        if(performSASLprep){
        	sASLPrepedPassword= Stringprep.saslprep(passphrase);
        }
        
        while(keyIndex < keylength){
        	SecretKey sk = new SecretKeySpec(currentKey,
        			sa.getJCEAlgorithmString());

        	Mac m = Mac.getInstance("HmacSHA1");
        	m.init(sk);
        	m.update(sASLPrepedPassword.getBytes("ISO8859-1"));
        	byte[] mac = m.doFinal();
        	for(int i=0;i<mac.length;i++){
               if(keyIndex < keylength){
            	   finalKey[keyIndex] = mac[i];
            	   keyIndex++;
               }else{
            	   break;
               }
        	}
        	mac[0] = (byte) (mac[0] ^ currentKey[0]);
        	currentKey = mac;
        	
        	retval = new SecretKeySpec(finalKey,
        			sa.getJCEAlgorithmString());
        }
		} catch(IllegalMonitorStateException e){
		    // TODO: remove this catch? It's needed?
            log.error("IllegalMonitorStateException", e);			
		} catch (ParserConfigurationException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (XMLSecurityException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (NoSuchAlgorithmException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (InvalidKeyException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (IllegalStateException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		} catch (UnsupportedEncodingException e) {
			log.error("Error generating secret key", e);
			throw new XMLEncryptionException(e.getMessage(),e);
		}
        
        return  retval;
	}
	
	/**
	 * Method appending a authorization keybinding element to
	 * a requestDoc
	 * 
	 * @param requestDoc
	 * @param passphrase
	 * @param prototypeKeyBindingId
	 * @return the requestDoc with authorization appended
	 * @throws StringprepException if the passphrase doesn't fullfull the SASLPrep profile
	 * @throws XMLSecurityException If any other exception occured during generation.
	 */
	public static Document appendKeyBindingAuthentication(Document requestDoc,String passphrase, String prototypeKeyBindingId) throws StringprepException, XMLSecurityException{
	   	SecretKey sk = XKMSUtil.getSecretKeyFromPassphrase(passphrase, true, 20, XKMSUtil.KEY_AUTHENTICATION);
		
		org.apache.xml.security.signature.XMLSignature authXMLSig = new org.apache.xml.security.signature.XMLSignature(requestDoc, "", org.apache.xml.security.signature.XMLSignature.ALGO_ID_MAC_HMAC_SHA1, org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		org.apache.xml.security.transforms.Transforms transforms = new org.apache.xml.security.transforms.Transforms(requestDoc);		
		transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		authXMLSig.addDocument("#" + prototypeKeyBindingId, transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);        			
	
		authXMLSig.sign(sk); 
		
		Element authenticationElement = requestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "Authentication");
		Element keyBindingAuthenticationElement = requestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "KeyBindingAuthentication");
		keyBindingAuthenticationElement.appendChild(authXMLSig.getElement().cloneNode(true));
		authenticationElement.appendChild(keyBindingAuthenticationElement);
		requestDoc.getDocumentElement().appendChild(authenticationElement);
        
        return requestDoc;
	}

    public static Document appendProofOfPossession(Document requestDoc,PrivateKey privateKey, String prototypeKeyBindingId)throws XMLSecurityException{
		org.apache.xml.security.signature.XMLSignature xmlSig = new org.apache.xml.security.signature.XMLSignature(requestDoc, "", org.apache.xml.security.signature.XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA1, org.apache.xml.security.c14n.Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		Transforms transforms = new org.apache.xml.security.transforms.Transforms(requestDoc);		
		transforms.addTransform(org.apache.xml.security.transforms.Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
		
		xmlSig.addDocument("#" + prototypeKeyBindingId, transforms, org.apache.xml.security.utils.Constants.ALGO_ID_DIGEST_SHA1);        			
	
		xmlSig.sign(privateKey);   
		
        Element pOPElement = requestDoc.createElementNS("http://www.w3.org/2002/03/xkms#", "ProofOfPossession");
        pOPElement.appendChild(xmlSig.getElement().cloneNode(true));
        requestDoc.getDocumentElement().appendChild(pOPElement);
        
        return requestDoc;
    }
	
}
