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
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.util.encoders.Base64;
import org.ejbca.core.protocol.ResponseStatus;
import org.ejbca.core.protocol.scep.ScepRequestGenerator;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.util.CertTools;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;

/**
 * Used to stress test the SCEP interface.
 * @author tomas
 * @version $Id$
 *
 */
class SCEPTest extends ClientToolBox {
	
	/** Inner class used to implement stress test framework 
	 * 
	 */
    static private class StressTest {
    	/** PerformaceTest framework, giving nice printed output */
        private final PerformanceTest performanceTest;

        // resources to access the SCEP servlet and verify RA and CA certificates
        private String url = "http://127.0.0.1:8080/scepraserver/scep/pkiclient.exe";
        private X509Certificate racert;
        private X509Certificate cacert;
        private X509Certificate rootcacert;
        
        private KeyPair keyPair = null;

        private final Random random = new Random();

        StressTest( final String url,
                    final int numberOfThreads,
                    final int waitTime
                    ) throws Exception {
            this.url = url;
            
            CertTools.installBCProviderIfNotAvailable();

            final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            this.keyPair = keygen.generateKeyPair();

            // Just initialize and take the performance penalty here, in vmware this can take a long time.
            this.random.nextInt();
            
            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(), numberOfThreads, waitTime, System.out);
        }

        /** Class with command to get certificate using SCEP.
         * It will detect if it is a CA that returns the certificate immediately, or an
         * RA that returns a "polling" answer so we have to poll for a little while.
         */
        private class GetCertificate implements Command {
            final private SessionData sessionData;
            GetCertificate(final SessionData sd) {
                this.sessionData = sd;
            }
            public boolean doIt() throws Exception {
                this.sessionData.newSession();

                // Start by retrieving the RA and CA certificates
            	boolean gotcacerts = scepGetCACertChain("GetCACertChain", "application/x-x509-ca-ra-cert-chain");    	
                if ( !gotcacerts ) {
                    StressTest.this.performanceTest.getLog().error("Error retrieving CACertChain.");
                    return false;
                }

            	// After this continue on with the SCPE requests
            	
                // Generate the SCEP GetCert request
                ScepRequestGenerator gen = new ScepRequestGenerator();                
                gen.setKeys(keyPair);
                gen.setDigestOid(CMSSignedGenerator.DIGEST_SHA1);
                String dn = this.sessionData.getUserDN();
                String transactionId = this.sessionData.getTransactionId();
                byte[] msgBytes = gen.generateCertReq(dn, "foo123", transactionId, racert);                    
                // Get some valuable things to verify later on
                String senderNonce = gen.getSenderNonce();

                // Send message with HTTP GET
                byte[] retMsg = sendScep(false, msgBytes, false);
                if ( retMsg == null ) {
                    StressTest.this.performanceTest.getLog().error("Error sending SCEP message.");
                    return false;
                }
                boolean okCertReq = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING);
                if ( !okCertReq ) {
                    StressTest.this.performanceTest.getLog().error("Error receiving response to CertReq request.");
                    return false;
                }
                // Send GetCertInitial and wait for a certificate response, you will probably get PENDING reply several times
                int keeprunning = 0;
                boolean processed = false;
                while ( (keeprunning < 5) && !processed) {
                	//System.out.println("Waiting 5 secs...");
                	Thread.sleep(5000); // wait 5 seconds between polls
                	// Generate a SCEP GerCertInitial message
                    gen.setKeys(keyPair);
                    gen.setDigestOid(CMSSignedGenerator.DIGEST_SHA1);
                    dn = this.sessionData.getUserDN(); // must be same as when the request was generated
                    msgBytes = gen.generateGetCertInitial(dn, transactionId, racert);                    
                    // Get some valuable things to verify later on
                    senderNonce = gen.getSenderNonce();
                	
                    // Send message with GET
                    retMsg = sendScep(false, msgBytes, false);
                    if ( retMsg == null ) {
                        StressTest.this.performanceTest.getLog().error("Error sending SCEP message.");
                        return false;
                    }
                    if (isScepResponseMessageOfType(retMsg, ResponseStatus.PENDING)) {
                    	StressTest.this.performanceTest.getLog().info("Received a PENDING message.");
                        boolean okPending = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING);            	
                        if ( !okPending ) {
                            StressTest.this.performanceTest.getLog().error("Error receiving pending response.");
                            return false;
                        }
                    } else {            	
                    	StressTest.this.performanceTest.getLog().info("Received a SUCCESS message.");
                        boolean okSuccess = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.SUCCESS);
                        if ( !okSuccess ) {
                            StressTest.this.performanceTest.getLog().error("Error receiving success response.");
                            return false;
                        }
                        processed = true;
                    }
                    keeprunning++;
                }
                if ( !processed ) {
                    StressTest.this.performanceTest.getLog().error("Processing failed.");
                    return false;
                }
                return true;
            }
            
            /** Send the pre-constructed scep request by HTTP and receive the immediate response
             */
            private byte[] sendScep(boolean post, byte[] scepPackage, boolean noca) throws IOException {
            	String urlString = url+"?operation=PKIOperation";
                HttpURLConnection con = null;
                if (post) {
                    URL url = new URL(urlString);
                    con = (HttpURLConnection)url.openConnection();
                    con.setDoOutput(true);
                    con.setRequestMethod("POST");
                    con.connect();
                    // POST it
                    OutputStream os = con.getOutputStream();
                    os.write(scepPackage);
                    os.close();
                } else {
                    String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)),"UTF-8");
                    URL url = new URL(reqUrl);
                    con = (HttpURLConnection)url.openConnection();
                    con.setRequestMethod("GET");
                    con.getDoOutput();
                    con.connect();
                }

                if ( con.getResponseCode()!=200 ) {
                    StressTest.this.performanceTest.getLog().error("Response code not 200: "+con.getResponseCode());
                    return null;
                }
                if ( !StringUtils.equals(con.getContentType(), "application/x-pki-message") ) {
                    StressTest.this.performanceTest.getLog().error("Content type not application/x-pki-message: "+con.getContentType());
                    return null;
                }

                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                // This works for small requests, and SCEP requests are small enough
                InputStream in = con.getInputStream();
                int b = in.read();
                while (b != -1) {
                    baos.write(b);
                    b = in.read();
                }
                baos.flush();
                in.close();
                byte[] respBytes = baos.toByteArray();
                if ( (respBytes == null) || (respBytes.length <= 0) ) {
                    StressTest.this.performanceTest.getLog().error("Response bytes is null or of 0 length");
                    return null;
                }
                return respBytes;
            } // sendScep

            /** Retrieves the RA and CA certificates from the SCEP RA
             *  
             */
            private boolean scepGetCACertChain(String method, String mimetype) throws Exception {
                String reqUrl = url+"?operation="+method+"&message=test";
                URL url = new URL(reqUrl);
                HttpURLConnection con = (HttpURLConnection)url.openConnection();
                con.setRequestMethod("GET");
                con.getDoOutput();
                con.connect();
                if ( con.getResponseCode()!=200 ) {
                    StressTest.this.performanceTest.getLog().error("Response code not 200: "+con.getResponseCode());
                    return false;
                }
                if ( !StringUtils.equals(con.getContentType(), mimetype) ) {
                    StressTest.this.performanceTest.getLog().error("Content type not "+mimetype+": "+con.getContentType());
                    return false;
                }
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                // This works for small requests, and SCEP requests are small enough
                InputStream in = con.getInputStream();
                int b = in.read();
                while (b != -1) {
                    baos.write(b);
                    b = in.read();
                }
                baos.flush();
                in.close();
                byte[] respBytes = baos.toByteArray();
                if ( (respBytes == null) || (respBytes.length <= 0) ) {
                    StressTest.this.performanceTest.getLog().error("Response bytes is null or of 0 length");
                    return false;
                }
                
                CMSSignedData s = new CMSSignedData(respBytes);
                SignerInformationStore signers = s.getSignerInfos();
                Collection col = signers.getSigners();
                if ( col.size() != 0) {
                    StressTest.this.performanceTest.getLog().error("signers should be 0");
                    return false;
                }
                CertStore certstore = s.getCertificatesAndCRLs("Collection","BC");
                Collection certs = certstore.getCertificates(null);
                // Length two if the Scep RA server is signed directly by a Root CA
                // Length three if the Scep RA server is signed by a CA which is signed by a Root CA
                if ( certs.size() != 3 ) {
                    StressTest.this.performanceTest.getLog().error("There should be 3 certificates: "+certs.size());
                    return false;
                }
                Iterator it = certs.iterator();
                racert = (X509Certificate)it.next();
                cacert = (X509Certificate)it.next();
                rootcacert = (X509Certificate)it.next();
                return true;
            }

            /** Method verifying various parts of the SCEP response message 
             * 
             */
            private boolean checkScepResponse(byte[] retMsg, String senderNonce, String transId, boolean crlRep, String digestOid, boolean noca, ResponseStatus expectedResponseStatus) throws CMSException, NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, InvalidKeyException, CertificateException, SignatureException, CRLException, IOException {
                //
                // Parse response message
                //
                CMSSignedData s = new CMSSignedData(retMsg);
                // The signer, i.e. the CA, check it's the right CA
                SignerInformationStore signers = s.getSignerInfos();
                Collection col = signers.getSigners();
                if ( col.size() <= 0 ) {
                    StressTest.this.performanceTest.getLog().error("Signers can not be 0");
                    return false;
                }
                Iterator iter = col.iterator();
                SignerInformation signerInfo = (SignerInformation)iter.next();
                // Check that the message is signed with the correct digest alg
                if ( !StringUtils.equals(digestOid, signerInfo.getDigestAlgOID()) ) {
                    StressTest.this.performanceTest.getLog().error("Digest algorithms do not match: "+digestOid+", "+signerInfo.getDigestAlgOID());
                    return false;
                }
                SignerId sinfo = signerInfo.getSID();
                // Check that the signer is the expected CA
                String raCertIssuer = CertTools.stringToBCDNString(racert.getIssuerDN().getName());
                String sinfoIssuer = CertTools.stringToBCDNString(sinfo.getIssuerAsString());
                if ( !StringUtils.equals(raCertIssuer, sinfoIssuer) ) {
                    StressTest.this.performanceTest.getLog().error("Issuers does not match: "+raCertIssuer+", "+sinfoIssuer);
                    return false;
                }

                // Verify the signature
                boolean ret = signerInfo.verify(racert.getPublicKey(), "BC");
                if ( !ret ) {
                    StressTest.this.performanceTest.getLog().error("Can not verify signerInfo");
                    return false;
                }
                // Get authenticated attributes
                AttributeTable tab = signerInfo.getSignedAttributes();        
                // --Fail info
                Attribute attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_failInfo));
                // No failInfo on this success message
                if(expectedResponseStatus == ResponseStatus.SUCCESS){
                    if ( attr != null ) {
                        StressTest.this.performanceTest.getLog().error("Success message should have attr == null");
                        return false;
                    }
                }  
                  
                // --Message type
                attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_messageType));
                if ( attr == null ) {
                    StressTest.this.performanceTest.getLog().error("MessageType should not be null for responseStatus: "+expectedResponseStatus);
                    return false;
                }
                ASN1Set values = attr.getAttrValues();
                if ( values.size() != 1 ) {
                    StressTest.this.performanceTest.getLog().error("MessageType.AttrValues should be 1: "+values.size());
                    return false;
                }
                DERString str = DERPrintableString.getInstance((values.getObjectAt(0)));
                String messageType = str.getString();
                if ( !StringUtils.equals(messageType, "3") ) {
                    StressTest.this.performanceTest.getLog().error("MessageType should be 3: "+messageType);
                    return false;
                }
                // --Success status
                attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_pkiStatus));
                if ( attr == null ) {
                    StressTest.this.performanceTest.getLog().error("PKIStatus should not be null");
                    return false;
                }
                values = attr.getAttrValues();
                if ( values.size() != 1 ) {
                    StressTest.this.performanceTest.getLog().error("PKIStatus.AttrValues should be 1: "+values.size());
                    return false;
                }
                str = DERPrintableString.getInstance((values.getObjectAt(0)));
                String responsestatus =  str.getString();
                if ( !StringUtils.equals(expectedResponseStatus.getValue(), responsestatus) ) {
                    StressTest.this.performanceTest.getLog().error("ResponseStatus should be "+expectedResponseStatus.getValue()+" but was: "+responsestatus);
                    return false;
                }
                // --SenderNonce
                attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_senderNonce));
                if ( attr == null ) {
                    StressTest.this.performanceTest.getLog().error("SenderNonce should not be null");
                    return false;
                }
                values = attr.getAttrValues();
                if ( values.size() != 1 ) {
                    StressTest.this.performanceTest.getLog().error("SenderNonce.AttrValues should be 1: "+values.size());
                    return false;
                }
                ASN1OctetString octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
                // SenderNonce is something the server came up with, but it should be 16 chars
                if ( octstr.getOctets().length != 16 ) {
                    StressTest.this.performanceTest.getLog().error("SenderNonce should be 16 bytes: "+octstr.getOctets().length);
                    return false;
                }
                // --Recipient Nonce
                attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_recipientNonce));
                if ( attr == null ) {
                    StressTest.this.performanceTest.getLog().error("RecipientNonce should not be null");
                    return false;
                }
                values = attr.getAttrValues();
                if ( values.size() != 1 ) {
                    StressTest.this.performanceTest.getLog().error("RecipientNonce.AttrValues should be 1: "+values.size());
                    return false;
                }
                octstr = ASN1OctetString.getInstance(values.getObjectAt(0));
                // recipient nonce should be the same as we sent away as sender nonce
                String nonce = new String(Base64.encode(octstr.getOctets()));
                if ( !StringUtils.equals(senderNonce, nonce) ) {
                    StressTest.this.performanceTest.getLog().error("RecipientNonce should be "+senderNonce+" but was: "+nonce);
                    return false;
                }
                // --Transaction ID
                attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_transId));
                if ( attr == null ) {
                    StressTest.this.performanceTest.getLog().error("TransId should not be null");
                    return false;
                }
                values = attr.getAttrValues();
                if ( values.size() != 1 ) {
                    StressTest.this.performanceTest.getLog().error("TransId.AttrValues should be 1: "+values.size());
                    return false;
                }
                str = DERPrintableString.getInstance((values.getObjectAt(0)));
                // transid should be the same as the one we sent
                if ( !StringUtils.equals(transId, str.getString()) ) {
                    StressTest.this.performanceTest.getLog().error("TransId should be "+transId+" but was: "+str.getString());
                    return false;
                }
                
                //
                // Check different message types
                //        
                if (!responsestatus.equals(ResponseStatus.PENDING.getValue()) && messageType.equals("3")) {
                    // First we extract the encrypted data from the CMS enveloped data contained
                    // within the CMS signed data
                    CMSProcessable sp = s.getSignedContent();
                    byte[] content = (byte[])sp.getContent();
                    CMSEnvelopedData ed = new CMSEnvelopedData(content);
                    RecipientInformationStore recipients = ed.getRecipientInfos();
                    Collection c = recipients.getRecipients();
                    if ( c.size() != 1 ) {
                        StressTest.this.performanceTest.getLog().error("recipients should be 1: "+c.size());
                        return false;
                    }
                    Iterator it = c.iterator();
                    byte[] decBytes = null;
                    RecipientInformation recipient = (RecipientInformation) it.next();
                    decBytes = recipient.getContent(keyPair.getPrivate(), "BC");
                    // This is yet another CMS signed data
                    CMSSignedData sd = new CMSSignedData(decBytes);
                    // Get certificates from the signed data
                    CertStore certstore = sd.getCertificatesAndCRLs("Collection","BC");
                    if (crlRep) {
                        // We got a reply with a requested CRL
                        Collection crls = certstore.getCRLs(null);
                        if ( crls.size() != 1 ) {
                            StressTest.this.performanceTest.getLog().error("CRLS should be 1: "+crls.size());
                            return false;
                        }
                        it = crls.iterator();
                        X509CRL retCrl = null;
                        // CRL is first (and only)
                        retCrl = (X509CRL)it.next();
                        //System.out.println("Got CRL with DN: "+ retCrl.getIssuerDN().getName());
//                        try {
//                            FileOutputStream fos = new FileOutputStream("sceptest.der");
//                            fos.write(retCrl.getEncoded());
//                            fos.close();
//                        } catch (Exception e) {}
                        // check the returned CRL
                        if ( !StringUtils.equals(cacert.getSubjectDN().getName(), retCrl.getIssuerDN().getName()) ) {
                            StressTest.this.performanceTest.getLog().error("CRL issuerDN should be "+cacert.getSubjectDN().getName()+" but was: "+retCrl.getIssuerDN().getName());
                            return false;
                        }
                        retCrl.verify(cacert.getPublicKey());
                    } else {
                        // We got a reply with a requested certificate 
                        Collection certs = certstore.getCertificates(null);
                        //System.out.println("Got certificate reply with certchain of length: "+certs.size());
                        // EJBCA returns the issued cert and the CA cert (cisco vpn client requires that the ca cert is included)
                        if (noca) {
                            if ( certs.size() != 1 ) {
                                StressTest.this.performanceTest.getLog().error("Certs should be 1: "+certs.size());
                                return false;
                            }
                        } else {
                            if ( certs.size() != 2 ) {
                                StressTest.this.performanceTest.getLog().error("Certs should be 2: "+certs.size());
                                return false;
                            }
                        }
                        it = certs.iterator();
                        // Issued certificate must be first
                        boolean verified = false;
                        boolean gotcacert = false;
                        X509Certificate usercert = null;
                        while (it.hasNext()) {
                            X509Certificate retcert = (X509Certificate)it.next();
//                            try {
//                                FileOutputStream fos = new FileOutputStream("sceptest.der");
//                                fos.write(retcert.getEncoded());
//                                fos.close();
//                            } catch (Exception e) {}
                        
                            // check the returned certificate
                            String subjectdn = CertTools.stringToBCDNString(retcert.getSubjectDN().getName());
                            String mysubjectdn = sessionData.getUserDN();
                            StressTest.this.performanceTest.getLog().info("subjectdn='"+subjectdn+"', mysubjectdn='"+mysubjectdn+"'.");
                            if (mysubjectdn.equals(subjectdn)) {
                                //System.out.println("Got user cert with DN: "+ retcert.getSubjectDN().getName());
                                // issued certificate
                                //System.out.println(retcert);
                                //System.out.println(cacert);
                                retcert.verify(cacert.getPublicKey());
                                boolean checked = checkKeys(keyPair.getPrivate(), retcert.getPublicKey());
                                if (!checked) {
                                    StressTest.this.performanceTest.getLog().error("keys does not match");
                                    return false;
                                }
                                verified = true;
                                String altName = CertTools.getSubjectAlternativeName(retcert);
                                if ( !StringUtils.equals("iPAddress=10.0.0.1, dNSName=foo.bar.com", altName) ) {
                                    StressTest.this.performanceTest.getLog().error("altName should be iPAddress=10.0.0.1, dNSName=foo.bar.com but was: "+altName);
                                    return false;
                                }
                                usercert = retcert;
                            } else {
                                //System.out.println("Got CA cert with DN: "+ retcert.getSubjectDN().getName());
                                // ca certificate
                                if ( !StringUtils.equals(cacert.getSubjectDN().getName(), retcert.getSubjectDN().getName()) ) {
                                    StressTest.this.performanceTest.getLog().error("CA certs subejctDN should be "+ cacert.getSubjectDN().getName() +" but was: "+retcert.getSubjectDN().getName());
                                    return false;
                                }
                                gotcacert = true;
                                usercert.verify(retcert.getPublicKey());
                            }
                        }
                        if (!verified) {
                            StressTest.this.performanceTest.getLog().error("cert does not verify");
                            return false;
                        }
                        if (noca) {
                            if (gotcacert) {
                                StressTest.this.performanceTest.getLog().error("got a CA cert when we should not have");
                                return false;
                            }
                        } else {
                            if (!gotcacert) {
                                StressTest.this.performanceTest.getLog().error("didn't get a CA cert when we should have");
                                return false;
                            }
                        }
                        StressTest.this.performanceTest.getLog().result(CertTools.getSerialNumber(usercert));

                    }
                }
                return true;
            } // checkScepResponse

            private boolean isScepResponseMessageOfType(byte[] retMsg, ResponseStatus extectedResponseStatus) throws CMSException, NoSuchAlgorithmException, NoSuchProviderException {
                //
                // Parse response message
                //
                CMSSignedData s = new CMSSignedData(retMsg);
                SignerInformationStore signers = s.getSignerInfos();
                Collection col = signers.getSigners();
                Iterator iter = col.iterator();
                SignerInformation signerInfo = (SignerInformation)iter.next();
                // Get authenticated attributes
                AttributeTable tab = signerInfo.getSignedAttributes();        
                Attribute attr = tab.get(new DERObjectIdentifier(ScepRequestMessage.id_pkiStatus));
                ASN1Set values = attr.getAttrValues();
                DERString str = DERPrintableString.getInstance((values.getObjectAt(0)));
                String responsestatus =  str.getString();
                if (extectedResponseStatus.getValue().equals(responsestatus)) {
                	return true;
                }
                return false;
            } // isScepResponseMessageOfType

            /**
             * checks that a public and private key matches by signing and verifying a message
             */
            private boolean checkKeys(PrivateKey priv, PublicKey pub) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
                Signature signer = Signature.getInstance("SHA1WithRSA");
                signer.initSign(priv);
                signer.update("PrimeKey".getBytes());
                byte[] signature = signer.sign();
                
                Signature signer2 = Signature.getInstance("SHA1WithRSA");
                signer2.initVerify(pub);
                signer2.update("PrimeKey".getBytes());
                return signer2.verify(signature);
            } // checkKeys

            public String getJobTimeDescription() {
                return "Get certificate";
            }
        }

        class SessionData {
            private String userDN;
            private String transactionId;
            SessionData() {
                super();
            }
            void newSession() {
                this.userDN = "CN=SCEP_Test_User_Nr_"+StressTest.this.random.nextInt()+",O=SCEP Test,C=SE";
                byte[] randBytes = new byte[16];
                StressTest.this.random.nextBytes(randBytes);
                byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
                transactionId = new String(Base64.encode(digest));
            }
            String getUserDN() {
                return this.userDN;
            }
            
            String getTransactionId() {
            	return this.transactionId;
            }
        } // class SessionData
        
        private class MyCommandFactory implements CommandFactory {
            public Command[] getCommands() throws Exception {
                final SessionData sessionData = new SessionData();
                return new Command[]{new GetCertificate(sessionData)};
            }
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    void execute(String[] args) {
        final String url;
        final int numberOfThreads;
        final int waitTime;
        if ( args.length < 2 ) {
            System.out.println(args[0]+" <SCEP url> [<number of threads>] [<wait time between each thread is started>]");
            System.out.println("SCEP URL is for example: http://127.0.0.1:8080/scepraserver/scep/pkiclient.exe");
            return;
        }
        url = args[1];
        numberOfThreads = args.length>2 ? Integer.parseInt(args[2].trim()):1;
        waitTime = args.length>3 ? Integer.parseInt(args[3].trim()):0;

        try {
            new StressTest(url, numberOfThreads, waitTime);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    String getName() {
        return "SCEPTest";
    }

}
