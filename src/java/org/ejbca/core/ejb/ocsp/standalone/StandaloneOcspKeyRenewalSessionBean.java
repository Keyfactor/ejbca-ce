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
package org.ejbca.core.ejb.ocsp.standalone;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;

import org.apache.log4j.Logger;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.ocsp.cache.CryptoTokenAndChain;
import org.cesecore.certificates.ocsp.standalone.StandaloneOcspResponseGeneratorSessionLocal;
import org.cesecore.config.OcspConfiguration;
import org.cesecore.internal.InternalResources;
import org.cesecore.jndi.JndiConstants;
import org.cesecore.keys.token.CryptoTokenOfflineException;
import org.cesecore.keys.token.KeyRenewalFailedException;
import org.cesecore.keys.util.KeyTools;
import org.cesecore.util.CertTools;
import org.ejbca.core.protocol.ws.client.gen.CertificateResponse;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWS;
import org.ejbca.core.protocol.ws.client.gen.EjbcaWSService;
import org.ejbca.core.protocol.ws.client.gen.NameAndId;
import org.ejbca.core.protocol.ws.client.gen.UserDataVOWS;
import org.ejbca.core.protocol.ws.client.gen.UserMatch;
import org.ejbca.core.protocol.ws.common.CertificateHelper;
import org.ejbca.util.query.BasicMatch;

/**
 * @version $Id$
 *
 */
@Stateless(mappedName = JndiConstants.APP_JNDI_PREFIX + "StandaloneOcspKeyRenewalSessionRemote")
@TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
public class StandaloneOcspKeyRenewalSessionBean implements StandaloneOcspKeyRenewalSessionLocal, StandaloneOcspKeyRenewalSessionRemote  {

    private static final Logger log = Logger.getLogger(StandaloneOcspKeyRenewalSessionBean.class);

    private static final InternalResources intres = InternalResources.getInstance();

    private static final String SIGNATURE_ALGORITHM = "SHA1WithRSA";

    @EJB
    private StandaloneOcspResponseGeneratorSessionLocal standaloneOcspResponseGeneratorSession;
    
    private EjbcaWS ejbcaWS;

    @PostConstruct
    public void postConstruct() {
       ejbcaWS = getEjbcaWS();
    }
    
    @Override
    public void renewKeyStores(String signerSubjectDN) {
        if (ejbcaWS == null) {
            return;
        }
        final X500Principal target;
        try {
            target = signerSubjectDN.trim().toLowerCase().equals(RENEW_ALL_KEYS) ? null : new X500Principal(signerSubjectDN);
        } catch (IllegalArgumentException e) {
            //TODO: ADD ocsp.rekey.triggered.dn.not.valid to intresources
            log.error(intres.getLocalizedMessage("ocsp.rekey.triggered.dn.not.valid", signerSubjectDN));
            return;
        }
        final StringBuffer matched = new StringBuffer();
        final StringBuffer unMatched = new StringBuffer();
        //TODO: Implement synchronization procedure, i.e. make sure nobody is using the keys as they are updated. 
        //TODO: Perhaps use a threaded solution for this so that it does as little blocking as possible
        Collection<CryptoTokenAndChain> cacheValues = standaloneOcspResponseGeneratorSession.getCacheValues();
        for (CryptoTokenAndChain tokenAndChain : cacheValues) {
            final X500Principal src = tokenAndChain.getChain()[0].getSubjectX500Principal();
            if (target != null && !src.equals(target)) {
                unMatched.append(" '" + src.getName() + '\'');
                continue;
            }
            matched.append(" '" + tokenAndChain.getChain()[0].getIssuerX500Principal().getName() + '\'');
            //Firstly, generate a new key pair and retrieve the public and private keys for future use.                
            try {
                PublicKey oldPublicKey;
                try {
                    oldPublicKey = tokenAndChain.getPublicKey();
                } catch (CryptoTokenOfflineException e) {
                    //TODO: Audit log operation failed for crypto token
                    continue;
                }
                final AlgorithmParameterSpec algorithmParameterSpec = KeyTools.getKeyGenSpec(oldPublicKey);
                if (!(algorithmParameterSpec instanceof RSAKeyGenParameterSpec)) {
                    log.info("Could not rekey " + src.getName() + ". Only RSA keys may be rekeyed");
                    continue;
                }
                final KeyPair keyPair = generateRSAKeyPair(algorithmParameterSpec, tokenAndChain.getSignProviderName());
                //Sign the new keypair
                X509Certificate signedCertificate = signCertificateByCa(tokenAndChain, keyPair);
                //Construct the new certificate chain
                final List<X509Certificate> lCertChain = Arrays.asList(tokenAndChain.getChain());
                lCertChain.add(0, signedCertificate);
                final X509Certificate certChain[] = lCertChain.toArray(new X509Certificate[0]);
              //  tokenAndChain.renewTokenAndChain(keyPair, certChain);
            } catch (KeyRenewalFailedException e) {
                //TODO: Audit log
                continue;
            } catch (IOException e) {
                log.error(e.getLocalizedMessage(), e);
            }

        }
        if (matched.length() < 1) {
            //TODO: ADD ocsp.rekey.triggered.dn.not.existing to intresources
            log.error(intres.getLocalizedMessage("ocsp.rekey.triggered.dn.not.existing", target.getName(), unMatched));
            return;
        }
        //TODO: ADD ocsp.rekey.triggered.dn.not.existing to intresources
        log.info(intres.getLocalizedMessage("ocsp.rekey.triggered", matched));

        //Caches need to be reloaded
        standaloneOcspResponseGeneratorSession.reloadTokenAndChainCache();
    }

    /**
     * This simple utility method constructs a RSA keypair. Any other keypair type will be rejected.
     * 
     * @param spec an {@link AlgorithmParameterSpec} that describes the keypair type. Can be derived from the public key.
     * @param providerName The name of the provider
     * @return a brand new keystore
     * @throws KeyRenewalFailedException if any error occurs.
     */
    private KeyPair generateRSAKeyPair(final AlgorithmParameterSpec spec, final String providerName) throws KeyRenewalFailedException {
        /* Developer's note: I know that there already are 4-5 examples of this method spread
         * around the codebase, but most of them are way too general. Since only RSA keys can be 
         * renamed, this variant is quick and easy.
         */
        if (!(spec instanceof RSAKeyGenParameterSpec)) {
            log.error("Only RSA keys could be renewed.");
            throw new IllegalArgumentException("Only RSA keys can be renewed.");
        }
        KeyPairGenerator kpg;
        try {
            kpg = KeyPairGenerator.getInstance("RSA", providerName);
            kpg.initialize(spec);
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new KeyRenewalFailedException("Algorithm RSA was not recognized", e);
        } catch (NoSuchProviderException e) {
            throw new IllegalArgumentException("Provider " + providerName + " was not found.", e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new KeyRenewalFailedException("Algorithm Parameter Specification was not of RSA type.", e);
        }
    }

    /**
     * Get user data for the EJBCA user that will be used when creating the cert for the new key.
     * @param ejbcaWS from {@link #getEjbcaWS()}
     * @return the data
     */
    private UserDataVOWS getUserDataVOWS(final X509Certificate signingCertificate, final int caId) {
        final UserMatch match = new UserMatch();
        final String subjectDN = CertTools.getSubjectDN(signingCertificate);
        final String caName = getCAName(caId);
        if(caName == null) {
            throw new InvalidParameterException("No CA found for ID: " + caId);
        }
        match.setMatchtype(BasicMatch.MATCH_TYPE_EQUALS);
        match.setMatchvalue(subjectDN);
        match.setMatchwith(org.ejbca.util.query.UserMatch.MATCH_WITH_DN);
        final List<UserDataVOWS> users;
        try {
            users = ejbcaWS.findUser(match);
        } catch (Exception e) {
            log.error("WS not working", e);
            return null;
        }
        if (users == null || users.size() < 1) {
            log.error(intres.getLocalizedMessage("ocsp.no.user.with.subject.dn", subjectDN));
            return null;
        }
        log.debug("at least one user found for cert with DN: " + subjectDN + " Trying to match it with CA name: " + caName);
        UserDataVOWS result = null;
        for(UserDataVOWS userData : users) {
            if (caName.equals(userData.getCaName())) {
                result = userData;
                break;
            }
        }
        if (result == null) {
            log.error("No user found for certificate '" + subjectDN + "' on CA '" + caName + "'.");
            return null;
        }
        return result;
    }

    /**
     * Get the CA name
     * @return the name
     */
    private String getCAName(int caId) {

        final Map<Integer, String> mCA = new HashMap<Integer, String>();
        try {
            for (NameAndId nameAndId : ejbcaWS.getAvailableCAs()) {
                mCA.put(new Integer(nameAndId.getId()), nameAndId.getName());
                log.debug("CA. id: " + nameAndId.getId() + " name: " + nameAndId.getName());
            }
        } catch (Exception e) {
            log.error("WS not working", e);
            return null;
        }
        return mCA.get(Integer.valueOf(caId));
    }

    /**
     * This method sends a keypair off to be signed by the CA that issued the original keychain.
     * 
     * @param tokenAndChain the {@link CryptoTokenAndChain} object destined to have a new keypair
     * @param keyPair the {@link KeyPair} to sign
     * @return a certificate that has been signed by the CA. 
     * @throws KeyRenewalFailedException if any error occurs during signing
     * @throws IOException 
     */
    @SuppressWarnings("unchecked")
    private X509Certificate signCertificateByCa(CryptoTokenAndChain tokenAndChain, KeyPair keyPair) throws KeyRenewalFailedException, IOException {
        /* Construct a certification request in order to have the new keystore certified by the CA. 
         */
        final int caId = CertTools.stringToBCDNString(tokenAndChain.getCaCertificate().getSubjectDN().toString()).hashCode();
        final UserDataVOWS userData = getUserDataVOWS(tokenAndChain.getChain()[0], caId);
        if(userData == null) {
          //TODO: Audit log 
            final String msg = "User data for certificate with subject DN: " + tokenAndChain.getChain()[0].getSubjectDN() + " was not found.";
            log.error(msg);
            throw new KeyRenewalFailedException(msg);
        }
        final PKCS10CertificationRequest pkcs10;
        try {
            pkcs10 = CertTools.genPKCS10CertificationRequest(SIGNATURE_ALGORITHM, CertTools.stringToBcX500Name("CN=NOUSED"), keyPair.getPublic(),
                    new DERSet(), keyPair.getPrivate(), tokenAndChain.getSignProviderName());

        } catch (NoSuchAlgorithmException e) {
            //TODO: Audit log 
            final String msg = "Signature algorithm " + SIGNATURE_ALGORITHM + " was not valid.";
            log.error(msg, e);
            throw new KeyRenewalFailedException(msg, e);
        } catch (NoSuchProviderException e) {
            //TODO: Audit log that provider from crypto token wasn't found.
            final String msg = "Provider from crypto token wasn't found";
            log.error(msg, e);
            throw new KeyRenewalFailedException(msg, e);
        } catch (InvalidKeyException e) {
            final String msg = "Private key was invalid";
            log.error(msg, e);
            //TODO: Audit log 
            throw new KeyRenewalFailedException(msg, e);
        } catch (SignatureException e) {
            final String msg = "Signature algorithm " + SIGNATURE_ALGORITHM + " was not valid. Could not create signature.";
            log.error(msg, e);
            throw new KeyRenewalFailedException("Private key was invalid", e);
        }

        CertificateResponse certificateResponse;
        try {
            certificateResponse = ejbcaWS.pkcs10Request(userData.getUsername(), userData.getPassword(),
                    new String(Base64.encode(pkcs10.getEncoded())), null, CertificateHelper.RESPONSETYPE_CERTIFICATE);
        } catch (Exception e) {
            //Way too many silly exceptions to handle, wrap instead.
            throw new KeyRenewalFailedException(e);
        }
        if(certificateResponse == null) {
            throw new KeyRenewalFailedException("Certificate Response was not received");
        }
        
        Collection<X509Certificate> certificates;
        try {
            certificates = (Collection<X509Certificate>) CertificateFactory.getInstance("X.509").generateCertificates(
                    new ByteArrayInputStream(Base64.decode(certificateResponse.getData())));
        } catch (CertificateException e) {
            throw new KeyRenewalFailedException(e);
        }
        
        X509Certificate signedCertificate = null;
        for(X509Certificate certificate : certificates) {
            try {
                certificate.verify(tokenAndChain.getChain()[0].getPublicKey());
            } catch (Exception e) {
                //Ugly, but inherited from legacy code
                signedCertificate = null;
                continue;
            }
            if ( keyPair.getPublic().equals(certificate.getPublicKey()) ) {
                signedCertificate = certificate;
                break;
            }           
        }
        if ( signedCertificate==null ) {
            throw new KeyRenewalFailedException("No certificate signed by correct CA generated.");
        }
        return signedCertificate;
    }

    @Override
    public void setEjbcaWs(EjbcaWS ejbcaWS) {
       this.ejbcaWS = ejbcaWS;      
    }

    /**
     * Get WS object.
     * 
     * Using this method instead of EJB injection because injection fails badly. 
     * 
     * @return the EJBCA WS object.
     */ 
    private EjbcaWS getEjbcaWS() {
        final URL ws_url;
        String webUrl = OcspConfiguration.getEjbcawsracliUrl();
        try {
            ws_url = new URL(webUrl + "?wsdl");
        } catch (MalformedURLException e) {
            log.error("Problem with URL: '" + webUrl + "'", e);
            return null;
        }
        final QName qname = new QName("http://ws.protocol.core.ejbca.org/", "EjbcaWSService");
        if (log.isDebugEnabled()) {
            log.debug("web service. URL: " + ws_url + " QName: " + qname);
        }
        return new EjbcaWSService(ws_url, qname).getEjbcaWSPort();
    }

}
