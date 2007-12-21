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
 
package org.ejbca.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.lang.reflect.Constructor;
import java.security.AuthProvider;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.PKCS12BagAttributeCarrier;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.ejbca.core.model.ca.catoken.CATokenConstants;


/**
 * Tools to handle common key and keystore operations.
 *
 * @version $Id: KeyTools.java,v 1.12 2007-12-21 13:36:39 primelars Exp $
 */
public class KeyTools {
    private static Logger log = Logger.getLogger(KeyTools.class);

    /** The name of Suns pkcs11 implementation */
    public static final String SUNPKCS11CLASS = "sun.security.pkcs11.SunPKCS11";
        
    /**
     * Prevent from creating new KeyTools object
     */
    private KeyTools() {
    }

    /**
     * Generates a keypair
     *
     * @param keyspec specification of keys to generate, typical value is 1024 for RSA keys or prime192v1 for ECDSA keys
     * @param keyalg algorithm of keys to generate, typical value is RSA or ECDSA, see org.ejbca.core.model.ca.catoken.CATokenConstants.KEYALGORITHM_XX
     * 
     * @see org.ejbca.core.model.ca.catoken.CATokenConstants
     * @see org.bouncycastle.asn1.x9.X962NamedCurves
     * @see org.bouncycastle.asn1.nist.NISTNamedCurves
     * @see org.bouncycastle.asn1.sec.SECNamedCurves
     * 
     * @return KeyPair the generated keypair
     * @throws InvalidAlgorithmParameterException 
     */
    public static KeyPair genKeys(String keySpec, String keyAlg)
        throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    	if (log.isDebugEnabled()) {
            log.debug(">genKeys("+keySpec+", "+keyAlg+")");    		
    	}

        KeyPairGenerator keygen = KeyPairGenerator.getInstance(keyAlg, "BC");
        if (StringUtils.equals(keyAlg, CATokenConstants.KEYALGORITHM_ECDSA)) {
        	org.bouncycastle.jce.spec.ECParameterSpec ecSpec = null;
        	if ( (keySpec == null) || StringUtils.equals(keySpec,"implicitlyCA") ) {
        		log.debug("Generating implicitlyCA encoded ECDSA key pair");
            	// If the keySpec is null, we have "implicitlyCA" defined EC parameters
        		// The parameters were already installed when we installed the provider
        		// We just make sure that ecSpec == null here
        	} else {
        		log.debug("Generating named curve ECDSA key pair");
            	// We have EC keys
            	ecSpec = ECNamedCurveTable.getParameterSpec(keySpec);        		
        	}
        	keygen.initialize(ecSpec, new SecureRandom());
        } else {
        	// RSA keys
        	int keysize = Integer.parseInt(keySpec);
            keygen.initialize(keysize);
        }

        KeyPair keys = keygen.generateKeyPair();

        if (log.isDebugEnabled()) {
            PublicKey pk = keys.getPublic();
        	int len = getKeyLength(pk);
            log.debug("Generated " + keys.getPublic().getAlgorithm() + " keys with length " + len);        	
    		log.debug("<genKeys()");
        }

        return keys;
    } // genKeys

    /**
     * Gets the key length of supported keys
     * @param priv PrivateKey to check
     * @return -1 if key is unsupported, otherwise a number >= 0. 0 usually means the length can not be calculated, 
     * for example if the key is en EC key and the "implicitlyCA" encoding is used.
     */
	public static int getKeyLength(PublicKey pk) {
		int len = -1;
		if (pk instanceof RSAPublicKey) {
			RSAPublicKey rsapub = (RSAPublicKey) pk;
			len = rsapub.getModulus().bitLength();
		} else if (pk instanceof JCEECPublicKey) {
			JCEECPublicKey ecpriv = (JCEECPublicKey) pk;
			org.bouncycastle.jce.spec.ECParameterSpec spec = ecpriv.getParameters();
			if (spec != null) {
				len = spec.getN().bitLength();				
			} else {
				// We support the key, but we don't know the key length
				len = 0;
			}
		} else if (pk instanceof ECPublicKey) {
			ECPublicKey ecpriv = (ECPublicKey) pk;
			java.security.spec.ECParameterSpec spec = ecpriv.getParams();
			if (spec != null) {
				len = spec.getOrder().bitLength(); // does this really return something we expect?
			} else {
				// We support the key, but we don't know the key length
				len = 0;
			}
		}
		return len;
	}

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape. The alias for the private key is
     * set to 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cacert CA-certificate or null if only one cert in chain, in that case use 'cert'.
     *
     * @return KeyStore containing PKCS12-keystore
     *
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, X509Certificate cacert) 
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;

        if (cacert == null) {
            chain = null;
        } else {
            chain = new Certificate[1];
            chain[0] = cacert;
        }

        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape.
     * The alias for the private key is set to 'privateKey' and the private key password is null.
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cacert Collection of X509Certificate, or null if only one cert in chain, in that case use 'cert'.
     * @param username user's username
     * @param password user's password
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Collection cacerts)
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        Certificate[] chain;
        if (cacerts == null)
            chain = null;
        else {
            chain = new Certificate[cacerts.size()];
            chain = (Certificate[])cacerts.toArray(chain);
        }
        return createP12(alias, privKey, cert, chain);
    } // createP12

    /**
     * Creates PKCS12-file that can be imported in IE or Netscape. The alias for the private key is
     * set to 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param cert user certificate
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use 'cert'.
     * @return KeyStore containing PKCS12-keystore
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createP12(String alias, PrivateKey privKey, X509Certificate cert, Certificate[] cachain) 
    throws IOException, KeyStoreException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        log.debug(">createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        Certificate[] chain = new Certificate[len];
        // To not get a ClassCastException we need to genereate a real new certificate with BC
        CertificateFactory cf = CertTools.getCertificateFactory();
        chain[0] = cf.generateCertificate(new ByteArrayInputStream(cert.getEncoded()));

        if (cachain != null) {
            for (int i = 0; i < cachain.length; i++) {
                X509Certificate tmpcert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                            cachain[i].getEncoded()));
                chain[i + 1] = tmpcert;
            }
        }
        if (chain.length > 1) {
            for (int i = 1; i < chain.length; i++) {
                X509Certificate cacert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(
                            chain[i].getEncoded()));
                // Set attributes on CA-cert
                PKCS12BagAttributeCarrier caBagAttr = (PKCS12BagAttributeCarrier) chain[i];
                // We constuct a friendly name for the CA, and try with some parts from the DN if they exist.
                String cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "CN");
                // On the ones below we +i to make it unique, O might not be otherwise
                if (cafriendly == null) {
                    cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "O")+i;
                }
                if (cafriendly == null) {
                    cafriendly = CertTools.getPartFromDN(CertTools.getSubjectDN(cacert), "OU"+i);
                }
                if (cafriendly == null) {
                    cafriendly = "CA_unknown"+i;
                }
                caBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName,
                    new DERBMPString(cafriendly));
            }
        }

        // Set attributes on user-cert
        PKCS12BagAttributeCarrier certBagAttr = (PKCS12BagAttributeCarrier) chain[0];
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        // in this case we just set the local key id to that of the public key
        certBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
        // "Clean" private key, i.e. remove any old attributes
        KeyFactory keyfact = KeyFactory.getInstance(privKey.getAlgorithm(), "BC");
        PrivateKey pk = keyfact.generatePrivate(new PKCS8EncodedKeySpec(privKey.getEncoded()));
        // Set attributes for private key
        PKCS12BagAttributeCarrier keyBagAttr = (PKCS12BagAttributeCarrier) pk;
        // in this case we just set the local key id to that of the public key
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_friendlyName, new DERBMPString(alias));
        keyBagAttr.setBagAttribute(PKCSObjectIdentifiers.pkcs_9_at_localKeyId, createSubjectKeyId(chain[0].getPublicKey()));
        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("PKCS12", "BC");
        store.load(null, null);
        store.setKeyEntry(alias, pk, null, chain);
        log.debug("<createP12: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) + ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        return store;
    } // createP12

    /**
     * Creates JKS-file that can be used with JDK. The alias for the private key is set to
     * 'privateKey' and the private key password is null.
     *
     * @param alias the alias used for the key entry
     * @param privKey RSA private key
     * @param password user's password
     * @param cert user certificate
     * @param cachain CA-certificate chain or null if only one cert in chain, in that case use
     *        'cert'.
     *
     * @return KeyStore containing JKS-keystore
     *
     * @exception Exception if input parameters are not OK or certificate generation fails
     */
    public static KeyStore createJKS(String alias, PrivateKey privKey, String password,
        X509Certificate cert, Certificate[] cachain) throws Exception {
        log.debug(">createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +
            ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        String caAlias = "cacert";

        // Certificate chain
        if (cert == null) {
            throw new IllegalArgumentException("Parameter cert cannot be null.");
        }
        int len = 1;
        if (cachain != null) {
            len += cachain.length;
        }
        Certificate[] chain = new Certificate[len];
        chain[0] = cert;
        if (cachain != null) {
            for (int i = 0; i < cachain.length; i++) {
                chain[i + 1] = cachain[i];
            }
        }

        // store the key and the certificate chain
        KeyStore store = KeyStore.getInstance("JKS");
        store.load(null, null);

        // First load the key entry
        X509Certificate[] usercert = new X509Certificate[1];
        usercert[0] = cert;
        store.setKeyEntry(alias, privKey, password.toCharArray(), usercert);

        // Add the root cert as trusted
        if (cachain != null) {
            if (!CertTools.isSelfSigned((X509Certificate) cachain[cachain.length - 1])) {
                throw new IllegalArgumentException("Root cert is not self-signed.");
            }
            store.setCertificateEntry(caAlias, cachain[cachain.length - 1]);
        }

        // Set the complete chain
        log.debug("Storing cert chain of length " + chain.length);
        store.setKeyEntry(alias, privKey, password.toCharArray(), chain);
        log.debug("<createJKS: alias=" + alias + ", privKey, cert=" + CertTools.getSubjectDN(cert) +
            ", cachain.length=" + ((cachain == null) ? 0 : cachain.length));

        return store;
    } // createJKS

    /**
     * Retrieves the certificate chain from a keystore.
     *
     * @param keyStore the keystore, which has been loaded and opened.
     * @param privateKeyAlias the alias of the privatekey for which the certchain belongs.
     *
     * @return array of Certificate, or null if no certificates are found.
     */
    public static Certificate[] getCertChain(KeyStore keyStore, String privateKeyAlias)
        throws KeyStoreException {
        log.debug(">getCertChain: alias='" + privateKeyAlias + "'");

        Certificate[] certchain = keyStore.getCertificateChain(privateKeyAlias);
        if (certchain == null) {
            return null;
        }
        log.debug("Certchain retrieved from alias '" + privateKeyAlias + "' has length " +
            certchain.length);

        if (certchain.length < 1) {
            log.error("Cannot load certificate chain with alias '" + privateKeyAlias +
                "' from keystore.");
            log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" +
                certchain.length);

            return certchain;
        } else if (certchain.length > 0) {
            if (CertTools.isSelfSigned((X509Certificate) certchain[certchain.length - 1])) {
                log.debug("Issuer='" +
                    CertTools.getIssuerDN((X509Certificate) certchain[certchain.length - 1]) +
                    "'.");
                log.debug("Subject='" +
                    CertTools.getSubjectDN((X509Certificate) certchain[certchain.length - 1]) +
                    "'.");
                log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" +
                    certchain.length);

                return certchain;
            }
        }

        // If we came here, we have a cert which is not root cert in 'cert'
        ArrayList array = new ArrayList();

        for (int i = 0; i < certchain.length; i++) {
            array.add(certchain[i]);
        }

        boolean stop = false;

        while (!stop) {
            X509Certificate cert = (X509Certificate) array.get(array.size() - 1);
            String ialias = CertTools.getPartFromDN(CertTools.getIssuerDN(cert), "CN");
            Certificate[] chain1 = keyStore.getCertificateChain(ialias);

            if (chain1 == null) {
                stop = true;
            } else {
                log.debug("Loaded certificate chain with length " + chain1.length +
                    " with alias '" + ialias + "'.");

                if (chain1.length == 0) {
                    log.error("No RootCA certificate found!");
                    stop = true;
                }

                for (int j = 0; j < chain1.length; j++) {
                    array.add(chain1[j]);

                    // If one cert is slefsigned, we have found a root certificate, we don't need to go on anymore
                    if (CertTools.isSelfSigned((X509Certificate) chain1[j])) {
                        stop = true;
                    }
                }
            }
        }

        Certificate[] ret = new Certificate[array.size()];

        for (int i = 0; i < ret.length; i++) {
            ret[i] = (X509Certificate) array.get(i);
            log.debug("Issuer='" + CertTools.getIssuerDN((X509Certificate) ret[i]) + "'.");
            log.debug("Subject='" + CertTools.getSubjectDN((X509Certificate) ret[i]) + "'.");
        }

        log.debug("<getCertChain: alias='" + privateKeyAlias + "', retlength=" + ret.length);

        return ret;
    } // getCertChain

    /**
     * create the subject key identifier.
     *
     * @param pubKey the public key
     *
     * @return SubjectKeyIdentifer asn.1 structure
     */
    public static SubjectKeyIdentifier createSubjectKeyId(PublicKey pubKey) {
        try {
            ByteArrayInputStream bIn = new ByteArrayInputStream(pubKey.getEncoded());
            SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(
                        bIn).readObject());

            return new SubjectKeyIdentifier(info);
        } catch (Exception e) {
            throw new RuntimeException("error creating key");
        }
    } // createSubjectKeyId
    
    /** Creates the SUN PKCS#11 provider using the passed in pkcs11 library.
     * 
     * @param slot pkcs11 slot number
     * @param libName the manufacturers provided pkcs11 library (.dll or .so) 
     * @return AuthProvider of type "sun.security.pkcs11.SunPKCS11"
     * @throws IOException if the pkcs11 library can not be found, or the SunPKCS11 can not be created.
     */ 
    public static AuthProvider getP11AuthProvider(final String slot, final String libName) throws IOException {
    	if (StringUtils.isEmpty(libName)) {
    		throw new IOException("A shared library PKCS11 file name must be supplied.");
    	}
    	final File libFile = new File(libName);
    	if ( !libFile.isFile() || !libFile.canRead() ) {
    		throw new IOException("The shared library PKCS11 file "+libName+" can't be read.");
    	}
    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
    	PrintWriter pw = new PrintWriter(baos);
    	pw.println("name = "+libFile.getName()+"-slot"+slot);
    	pw.println("library = "+libFile.getCanonicalPath());
    	if ( (slot != null) && (slot.length() > 0) ) {
        	pw.println("slot = "+slot);    		
    	}
        pw.println("attributes(generate,*,*) = {");
        pw.println("  CKA_UNWRAP = true");
        pw.println("  CKA_DECRYPT = true");
        pw.println("  CKA_SIGN = true");
        pw.println("}");
        pw.flush();
    	pw.close();
    	if (log.isDebugEnabled()) {
    		log.debug(baos.toString());
    	}

        // We will construct the PKCS11 provider (sun.security...) using reflextion, because 
        // the sun class does not exist on all platforms in jdk5, and we want to be able to compile everything.
        // The below code replaces the single line:
        //   return new SunPKCS11(new ByteArrayInputStream(baos.toByteArray()));
    	try {
    		final Class implClass = Class.forName(SUNPKCS11CLASS);
    		final Constructor construct = implClass.getConstructor(InputStream.class);
    		final ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
    		return (AuthProvider)construct.newInstance(new Object[] {bais});
    	} catch (Exception e) {
    		log.error("Error constructing pkcs11 provider: ", e);
    		IOException ioe = new IOException("Error constructing pkcs11 provider: "+e.getMessage());
    		ioe.initCause(e);
    		throw ioe;
    	} 
    }

} // KeyTools
