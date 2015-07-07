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
package org.ejbca.ui.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.apache.log4j.Logger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.certificates.util.AlgorithmConstants;
import org.cesecore.certificates.util.AlgorithmTools;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;
import org.ejbca.util.PerformanceTest.NrOfThreadsAndNrOfTests;

/**
 * Used to stress test the SCEP interface.
 *
 * @version $Id$
 */
class SCEPTest extends ClientToolBox {
	
	/** Inner class used to implement stress test framework */
    static private class StressTest {
    	/** PerformaceTest framework, giving nice printed output */
        private final PerformanceTest performanceTest;

        // resources to access the SCEP servlet and verify RA and CA certificates
        final private String url;
        
        final private KeyPair keyPair;

        private final Random random = new Random();
        private final String caName;

        StressTest( final String url,
                    final int numberOfThreads,
                    final int numberOfTests,
                    final int waitTime,
                    final String caName,
                    final String userCNBase
                    ) throws Exception {
            this.url = url;
            this.caName = caName;
            
            CryptoProviderTools.installBCProviderIfNotAvailable();

            final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(1024);
            this.keyPair = keygen.generateKeyPair();

            // Just initialize and take the performance penalty here, in vmware this can take a long time.
            this.random.nextInt();
            
            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(userCNBase), numberOfThreads, numberOfTests, waitTime, System.out);
        }

        private class ScepGetCACertChain implements Command {
            /** Retrieves the RA and CA certificates from the SCEP RA
             *  
             */
            final private SessionData sessionData;
            ScepGetCACertChain(final SessionData sd) {
                super();
                this.sessionData = sd;
            }
            public boolean doIt() throws Exception {
                final String mimetype = "application/x-x509-ca-ra-cert-chain";
                final String reqUrl = StressTest.this.url+"?operation=GetCACertChain&message="+StressTest.this.caName;
                final HttpURLConnection con = (HttpURLConnection)new URL(reqUrl).openConnection();
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
                final CMSSignedData s = new CMSSignedData(con.getInputStream());
                @SuppressWarnings("rawtypes")
                final Store certstore = s.getCertificates();
                @SuppressWarnings("unchecked")
                final X509Certificate[] certs = CertTools.convertToX509CertificateArray(certstore.getMatches(null));
                // Length two if the Scep RA server is signed directly by a Root CA
                // Length three if the Scep RA server is signed by a CA which is signed by a Root CA
                if ( this.sessionData.certchain!=null && this.sessionData.certchain.length!=certs.length ) {
                    StressTest.this.performanceTest.getLog().error("Length of received certificate chain "+certs.length+" but should be "+this.sessionData.certchain.length);
                    return false;
                }
                for (int i=0; i<certs.length; i++) {
                    if ( this.sessionData.certchain==null ) {
                        StressTest.this.performanceTest.getLog().info("Cert "+i+" "+certs[i].getSubjectDN());
                    } else if ( !certs[i].equals(this.sessionData.certchain[i]) ) {
                        StressTest.this.performanceTest.getLog().error("New cert chain is not equal to old!");
                        return false;
                    }
                }
                this.sessionData.certchain = certs;
                return true;
            }
            public String getJobTimeDescription() {
                return "Get certificate chain";
            }
        }

        private Extensions generateExtensions(int bcKeyUsage) throws IOException {
            final ExtensionsGenerator extgen = new ExtensionsGenerator();
            extgen.addExtension(Extension.keyUsage, false, new X509KeyUsage(bcKeyUsage));
            final GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo.bar.com,iPAddress=10.0.0.1");
            extgen.addExtension(Extension.subjectAlternativeName, false, san);
            return extgen.generate();
        }

        /** Class with command to get certificate using SCEP.
         * It will detect if it is a CA that returns the certificate immediately, or an
         * RA that returns a "polling" answer so we have to poll for a little while.
         */
        private class GetCertificate implements Command {
            final private SessionData sessionData;
            final private String userCN;
            GetCertificate(final SessionData sd, String _userCN) {
                super();
                this.sessionData = sd;
                this.userCN = _userCN;
            }
            public boolean doIt() throws Exception {
                final String userDN;
                final String transactionId;
                {
                    final String trailingDN = ",O=SCEP Test,C=SE";
                    if ( this.userCN!=null ) {
                        userDN = "CN="+this.userCN+trailingDN;
                    } else {
                        userDN = "CN=SCEP_Test_User_Nr_"+StressTest.this.random.nextInt()+trailingDN;
                    }
                    byte[] randBytes = new byte[16];
                    StressTest.this.random.nextBytes(randBytes);
                    byte[] digest = CertTools.generateMD5Fingerprint(randBytes);
                    transactionId = new String(Base64.encode(digest));
                }

            	// After this continue on with the SCPE requests
            	
                // Generate the SCEP GetCert request
                final ScepRequestGenerator gen = new ScepRequestGenerator();                
                gen.setKeys(StressTest.this.keyPair, BouncyCastleProvider.PROVIDER_NAME);
                gen.setDigestOid(CMSSignedGenerator.DIGEST_SHA1);
                final int keyUsagelength = 9;
                final boolean keyUsage[] = new boolean[keyUsagelength];
                {
                    final byte[] msgBytes;
                    {
                        int bcKeyUsage = 0;
                        for ( int i=0; i<keyUsagelength; i++ ) {
                            keyUsage[i] = StressTest.this.random.nextBoolean();
                            if ( keyUsage[i] ) {
                                bcKeyUsage += i<8 ? 1<<(7-i) : 1<<(15+8-i);
                            }
                        }
                        X509Certificate senderCertificate = CertTools.genSelfCert(userDN, 24 * 60 * 60 * 1000, null,
                                StressTest.this.keyPair.getPrivate(), StressTest.this.keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                                false);
                        msgBytes = gen.generateCertReq(userDN, "foo123", transactionId, this.sessionData.certchain[0],
                                generateExtensions(bcKeyUsage), senderCertificate, StressTest.this.keyPair.getPrivate());                 
                    }
                    // Get some valuable things to verify later on
                    final String senderNonce = gen.getSenderNonce();

                    // Send message with HTTP GET
                    final byte[] retMsg = sendScep(false, msgBytes);
                    if ( retMsg == null ) {
                        StressTest.this.performanceTest.getLog().error("Error sending SCEP message.");
                        return false;
                    }
                    if (!isScepResponseMessageOfType(retMsg, ResponseStatus.PENDING)) {
                        final boolean okSuccess = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, true, ResponseStatus.SUCCESS, userDN, keyUsage);
                        if ( !okSuccess ) {
                            StressTest.this.performanceTest.getLog().error("Error receiving success response.");
                            return false;
                        }
                        return true;
                    }
                    final boolean okCertReq = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING, userDN, keyUsage);
                    if ( !okCertReq ) {
                        StressTest.this.performanceTest.getLog().error("Error receiving response to CertReq request.");
                        return false;
                    }
                }
                // Send GetCertInitial and wait for a certificate response, you will probably get PENDING reply several times
                for ( int keeprunning = 0; keeprunning<5; keeprunning++) {
                	//System.out.println("Waiting 5 secs...");
                	Thread.sleep(5000); // wait 5 seconds between polls
                	// Generate a SCEP GerCertInitial message
                    gen.setKeys(StressTest.this.keyPair, BouncyCastleProvider.PROVIDER_NAME);
                    gen.setDigestOid(CMSSignedGenerator.DIGEST_SHA1);
                    X509Certificate senderCertificate = CertTools.genSelfCert(userDN, 24 * 60 * 60 * 1000, null,
                            StressTest.this.keyPair.getPrivate(), StressTest.this.keyPair.getPublic(), AlgorithmConstants.SIGALG_SHA1_WITH_RSA,
                            false);
                    final byte[] msgBytes = gen.generateGetCertInitial(userDN, transactionId, this.sessionData.certchain[0], senderCertificate, StressTest.this.keyPair.getPrivate());                    
                    // Get some valuable things to verify later on
                    final String senderNonce = gen.getSenderNonce();
                	
                    // Send message with GET
                    final byte retMsg[] = sendScep(false, msgBytes);
                    if ( retMsg == null ) {
                        StressTest.this.performanceTest.getLog().error("Error sending SCEP message.");
                        return false;
                    }
                    if (isScepResponseMessageOfType(retMsg, ResponseStatus.PENDING)) {
                    	StressTest.this.performanceTest.getLog().info("Received a PENDING message.");
                        boolean okPending = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.PENDING, userDN, keyUsage);            	
                        if ( !okPending ) {
                            StressTest.this.performanceTest.getLog().error("Error receiving pending response.");
                            return false;
                        }
                    } else {            	
                    	StressTest.this.performanceTest.getLog().info("Received a SUCCESS message.");
                        boolean okSuccess = checkScepResponse(retMsg, senderNonce, transactionId, false, CMSSignedGenerator.DIGEST_SHA1, false, ResponseStatus.SUCCESS, userDN, keyUsage);
                        if ( !okSuccess ) {
                            StressTest.this.performanceTest.getLog().error("Error receiving success response.");
                            return false;
                        }
                        return true;
                    }
                }
                StressTest.this.performanceTest.getLog().error("Processing failed.");
                return false;
            }
            
            /** Send the pre-constructed scep request by HTTP and receive the immediate response
             */
            private byte[] sendScep(boolean post, byte[] scepPackage) throws IOException {
            	String urlString = StressTest.this.url+"?operation=PKIOperation";
                HttpURLConnection con = null;
                if (post) {
                    con = (HttpURLConnection)new URL(urlString).openConnection();
                    con.setDoOutput(true);
                    con.setRequestMethod("POST");
                    con.connect();
                    // POST it
                    OutputStream os = con.getOutputStream();
                    os.write(scepPackage);
                    os.close();
                } else {
                    String reqUrl = urlString + "&message=" + URLEncoder.encode(new String(Base64.encode(scepPackage)),"UTF-8");
                    con = (HttpURLConnection)new URL(reqUrl).openConnection();
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


            /** Method verifying various parts of the SCEP response message 
             * @throws OperatorCreationException 
             * 
             */
            private boolean checkScepResponse(byte[] retMsg, String senderNonce, String transId, boolean crlRep, String digestOid, boolean noca,
                    ResponseStatus expectedResponseStatus, String userDN, boolean[] keyUsage) throws CMSException, NoSuchProviderException,
                    NoSuchAlgorithmException, CertStoreException, InvalidKeyException, CertificateException, SignatureException, CRLException,
                    IOException, OperatorCreationException {
            	// Parse response message
            	//
            	CMSSignedData s = new CMSSignedData(retMsg);
            	// The signer, i.e. the CA, check it's the right CA
            	SignerInformationStore signers = s.getSignerInfos();
            	Collection<?> col = signers.getSigners();
            	if ( col.size() <= 0 ) {
            		StressTest.this.performanceTest.getLog().error("Signers can not be 0");
            		return false;
            	}
            	Iterator<?> iter = col.iterator();
            	SignerInformation signerInfo = (SignerInformation)iter.next();
            	// Check that the message is signed with the correct digest alg
            	if ( !StringUtils.equals(digestOid, signerInfo.getDigestAlgOID()) ) {
            		StressTest.this.performanceTest.getLog().error("Digest algorithms do not match: "+digestOid+", "+signerInfo.getDigestAlgOID());
            		return false;
            	}
            	SignerId sinfo = signerInfo.getSID();
            	// Check that the signer is the expected CA
            	String raCertIssuer = CertTools.stringToBCDNString(this.sessionData.certchain[0].getIssuerDN().getName());
            	String sinfoIssuer = CertTools.stringToBCDNString(sinfo.getIssuer().toString());
            	if ( !StringUtils.equals(raCertIssuer, sinfoIssuer) ) {
            		StressTest.this.performanceTest.getLog().error("Issuers does not match: "+raCertIssuer+", "+sinfoIssuer);
            		return false;
            	}
                // Verify the signature
            	JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoVerifierBuilder jcaSignerInfoVerifierBuilder = new JcaSignerInfoVerifierBuilder(calculatorProviderBuilder.build()).setProvider(BouncyCastleProvider.PROVIDER_NAME);
                boolean ret = signerInfo.verify(jcaSignerInfoVerifierBuilder.build(this.sessionData.certchain[0].getPublicKey()));
            	if ( !ret ) {
            		StressTest.this.performanceTest.getLog().error("Can not verify signerInfo");
            		return false;
            	}
            	// Get authenticated attributes
            	AttributeTable tab = signerInfo.getSignedAttributes();        
            	// --Fail info
            	Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_failInfo));
            	// No failInfo on this success message
            	if(expectedResponseStatus == ResponseStatus.SUCCESS){
            		if ( attr != null ) {
            			StressTest.this.performanceTest.getLog().error("Success message should have attr == null");
            			return false;
            		}
            	}  

            	// --Message type
            	attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType));
            	if ( attr == null ) {
            		StressTest.this.performanceTest.getLog().error("MessageType should not be null for responseStatus: "+expectedResponseStatus);
            		return false;
            	}
            	ASN1Set values = attr.getAttrValues();
            	if ( values.size() != 1 ) {
            		StressTest.this.performanceTest.getLog().error("MessageType.AttrValues should be 1: "+values.size());
            		return false;
            	}
            	ASN1String str = DERPrintableString.getInstance((values.getObjectAt(0)));
            	String messageType = str.getString();
            	if ( !StringUtils.equals(messageType, "3") ) {
            		StressTest.this.performanceTest.getLog().error("MessageType should be 3: "+messageType);
            		return false;
            	}
            	// --Success status
            	attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
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
            	if ( !StringUtils.equals(expectedResponseStatus.getStringValue(), responsestatus) ) {
            		StressTest.this.performanceTest.getLog().error("ResponseStatus should be "+expectedResponseStatus.getValue()+" but was: "+responsestatus);
            		return false;
            	}
            	// --SenderNonce
            	attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce));
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
            	attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_recipientNonce));
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
            	attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_transId));
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
            	if ( responsestatus.equals(ResponseStatus.PENDING.getValue()) || !messageType.equals("3") ) {
            		return true;
            	}
            	// First we extract the encrypted data from the CMS enveloped data contained
            	// within the CMS signed data
            	final CMSProcessable sp = s.getSignedContent();
            	final byte content[] = (byte[])sp.getContent();
            	final CMSEnvelopedData ed = new CMSEnvelopedData(content);
            	final RecipientInformationStore recipients = ed.getRecipientInfos();
            	final RecipientInformation recipient;
            	{
            		final Collection<?> c = recipients.getRecipients();
            		if ( c.size() != 1 ) {
            			StressTest.this.performanceTest.getLog().error("recipients should be 1: "+c.size());
            			return false;
            		}
            		final Iterator<?> it = c.iterator();
            		recipient = (RecipientInformation) it.next();
            	}
                JceKeyTransEnvelopedRecipient rec = new JceKeyTransEnvelopedRecipient(StressTest.this.keyPair.getPrivate());
                rec.setProvider(BouncyCastleProvider.PROVIDER_NAME);
                rec.setContentProvider(BouncyCastleProvider.PROVIDER_NAME);
                final byte decBytes[] = recipient.getContent(rec);
            	// This is yet another CMS signed data
            	final CMSSignedData sd = new CMSSignedData(decBytes);
            	// Get certificates from the signed data
                @SuppressWarnings("rawtypes")
                final Store certstore = sd.getCertificates();
            	if (crlRep) {
            		// We got a reply with a requested CRL
            		@SuppressWarnings("unchecked")
                    final Collection<X509CRL> crls = CertTools.convertToX509CRLList(sd.getCRLs().getMatches(null));
            		if (crls.size() != 1) {
            			StressTest.this.performanceTest.getLog().error("CRLS should be 1: "+crls.size());
            			return false;
            		}
                    final X509CRL retCrl = crls.iterator().next();
            		//System.out.println("Got CRL with DN: "+ retCrl.getIssuerDN().getName());
            		//                        try {
            		//                            FileOutputStream fos = new FileOutputStream("sceptest.der");
            		//                            fos.write(retCrl.getEncoded());
            		//                            fos.close();
            		//                        } catch (Exception e) {}
            		// check the returned CRL
            		if ( !StringUtils.equals(this.sessionData.certchain[1].getSubjectDN().getName(), retCrl.getIssuerDN().getName()) ) {
            			StressTest.this.performanceTest.getLog().error("CRL issuerDN should be "+this.sessionData.certchain[1].getSubjectDN().getName()+" but was: "+retCrl.getIssuerDN().getName());
            			return false;
            		}
            		retCrl.verify(this.sessionData.certchain[1].getPublicKey());
            		return true;
            	}
            	// We got a reply with a requested certificate 
            	@SuppressWarnings("unchecked")
                final List<X509Certificate> certs = CertTools.convertToX509CertificateList(certstore.getMatches(null));
            	//System.out.println("Got certificate reply with certchain of length: "+certs.size());
            	// EJBCA returns the issued cert and the CA cert (cisco vpn client requires that the ca cert is included)
            	final X509Certificate usercert;
            	final X509Certificate cacert;
            	if (noca) {
            		if ( certs.size() != 1 ) {
            			StressTest.this.performanceTest.getLog().error("Certs should be 1: "+certs.size());
            			return false;
            		}
            		usercert = certs.iterator().next();
            		cacert = null;
            	} else {
            		if ( certs.size() != 2 ) {
            			StressTest.this.performanceTest.getLog().error("Certs should be 2: "+certs.size());
            			return false;
            		}
            		final Iterator<X509Certificate> it = certs.iterator();
            		usercert = it.next();
            		cacert = it.next();
            	}
            	// Issued certificate must be first
            	//                            try {
            	//                                FileOutputStream fos = new FileOutputStream("sceptest.der");
            	//                                fos.write(retcert.getEncoded());
            	//                                fos.close();
            	//                            } catch (Exception e) {}

            	// check the returned certificate
            	final String subjectdn = CertTools.stringToBCDNString(usercert.getSubjectDN().getName());
            	if ( !subjectdn.equals(userDN) ) {
            		StressTest.this.performanceTest.getLog().info("subjectdn='"+subjectdn+"', mysubjectdn='"+userDN+"'.");
            		return false;
            	}
            	//System.out.println("Got user cert with DN: "+ retcert.getSubjectDN().getName());
            	// issued certificate
            	//System.out.println(retcert);
            	//System.out.println(cacert);
            	usercert.verify(this.sessionData.certchain[noca ? 0:1].getPublicKey());
            	if ( !checkKeys(StressTest.this.keyPair.getPrivate(), usercert.getPublicKey()) ) {
            		StressTest.this.performanceTest.getLog().error("keys does not match");
            		return false;
            	}
            	final String altName = CertTools.getSubjectAlternativeName(usercert);
            	final String expectedAltName = CertTools.getGeneralNamesFromAltName("iPAddress=10.0.0.1, dNSName=foo.bar.com").toString();
            	if (altName==null || CertTools.getGeneralNamesFromAltName(altName).equals(expectedAltName)) {
                    StressTest.this.performanceTest.getLog().error("altName should be " + expectedAltName + " but was: " + altName);
                    return false;
            	}
            	if ( cacert!=null ) {
            		//System.out.println("Got CA cert with DN: "+ retcert.getSubjectDN().getName());
            		// ca certificate
            		if ( !StringUtils.equals(this.sessionData.certchain[1].getSubjectDN().getName(), cacert.getSubjectDN().getName()) ) {
            			StressTest.this.performanceTest.getLog().error("CA certs subejctDN should be "+ this.sessionData.certchain[1].getSubjectDN().getName() +" but was: "+usercert.getSubjectDN().getName());
            			return false;
            		}
            		usercert.verify(cacert.getPublicKey());
            	}
            	if ( !Arrays.equals(usercert.getKeyUsage(), keyUsage) ) {
            	    StressTest.this.performanceTest.getLog().error("Key usage not OK. Is: '"+usercert.getKeyUsage()+"'. Should be '"+keyUsage+"'.");
            	    return false;
            	}
            	StressTest.this.performanceTest.getLog().result(CertTools.getSerialNumber(usercert));
                StressTest.this.performanceTest.getLog().info(usercert.toString());
            	return true;
            } // checkScepResponse

            private boolean isScepResponseMessageOfType(byte[] retMsg, ResponseStatus extectedResponseStatus) throws CMSException {
                //
                // Parse response message
                //
                CMSSignedData s = new CMSSignedData(retMsg);
                SignerInformationStore signers = s.getSignerInfos();
                Collection<?> col = signers.getSigners();
                Iterator<?> iter = col.iterator();
                SignerInformation signerInfo = (SignerInformation)iter.next();
                // Get authenticated attributes
                AttributeTable tab = signerInfo.getSignedAttributes();        
                Attribute attr = tab.get(new ASN1ObjectIdentifier(ScepRequestMessage.id_pkiStatus));
                ASN1Set values = attr.getAttrValues();
                ASN1String str = DERPrintableString.getInstance((values.getObjectAt(0)));
                String responsestatus =  str.getString();
                if (extectedResponseStatus.getStringValue().equals(responsestatus)) {
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
            X509Certificate[] certchain;
        } // class SessionData
        
        private class MyCommandFactory implements CommandFactory {
            final String userCommonNameBase;
            int nr = 0;
            MyCommandFactory(String _userCommonNameBase) {
                super();
                this.userCommonNameBase = _userCommonNameBase;
            }
            public Command[] getCommands() throws Exception {
                final SessionData sessionData = new SessionData();
                return new Command[]{new ScepGetCACertChain(sessionData),
                                     new GetCertificate(sessionData, this.userCommonNameBase!=null ? this.userCommonNameBase+(++this.nr) : null)};
            }
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
	protected void execute(String[] args) {
        final String url;
        final NrOfThreadsAndNrOfTests notanot;
        final int waitTime;
        final String caName;
        final String userCNBase;
        if ( args.length < 3 ) {
            System.out.println(args[0]+" <SCEP url> <CA name> [<number of threads>] [<wait time between each thread is started>] [<user CN to be prepended by >]");
            System.out.println("SCEP URL extra example: http://127.0.0.1:8080/scepraserver/scep/pkiclient.exe");
            System.out.println("SCEP URL ca example: http://localhost:8080/ejbca/publicweb/apply/scep/noca/pkiclient.exe");
            System.out.println();
            System.out.println("The test requires that your configured SCEP alias 'noca':");
            System.out.println("- is a configured to never returns the CA certificate.");
            System.out.println("- references a certificate profile with allowExtensionOverride=true and allow 1024 bit keys.");
            System.out.println("- references an end entity profile with 'Use' 'Batch generation");
            System.out.println();
            System.out.println("NOTE: This test should work for both EJBCA and EXTRA.");
            System.out.println("Originally it was written for EXTRA. But then it was change to use EJBCA directly also.");
            System.out.println("After the change it has not been verified that it is still working with EXTRA.");
            System.out.println("If you got problems with EXTRA you may revert back to the old version which is 8099 in SVN");
            return;
        }
        url = args[1];
        caName = args[2];
        notanot = new NrOfThreadsAndNrOfTests(args.length>3 ? args[3] : null);
        waitTime = args.length>4 ? Integer.parseInt(args[4].trim()):0;
        userCNBase = args.length>5 ? args[5] : null;

        try {
            new StressTest(url, notanot.threads, notanot.tests, waitTime, caName, userCNBase);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "SCEPTest";
    }
    
    private static class ScepRequestGenerator {
        private static Logger log = Logger.getLogger(ScepRequestGenerator.class);

        private X509Certificate cacert = null;
        private String reqdn = null;
        private KeyPair keys = null;
        private String signatureProvider = null;
        private String digestOid = CMSSignedGenerator.DIGEST_SHA1;
        private String senderNonce = null;

        /** A good random source for nounces, can take a long time to initialize on vmware */
        private static SecureRandom randomSource = null;

        public ScepRequestGenerator() {
            try { 
                if (randomSource == null) {
                    randomSource = SecureRandom.getInstance("SHA1PRNG");                
                }
            } catch (Exception e) {
                log.error(e);
            }
        }
        
        public void setKeys(KeyPair myKeys, String signatureProvider) {
            this.keys = myKeys;
            this.signatureProvider = signatureProvider;
        }
        public void setDigestOid(String oid) {
            digestOid = oid;
        }
        /** Base 64 encode senderNonce
         */
        public String getSenderNonce() {
            return senderNonce;
        }

        public byte[] generateCertReq(String dn, String password, String transactionId, X509Certificate ca, Extensions exts,
                final X509Certificate senderCertificate, final PrivateKey signatureKey) throws OperatorCreationException, CertificateException,
                IOException, CMSException {
            this.cacert = ca;
            this.reqdn = dn;
            // Generate keys

            // Create challenge password attribute for PKCS10
            // Attributes { ATTRIBUTE:IOSet } ::= SET OF Attribute{{ IOSet }}
            //
            // Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
            //    type    ATTRIBUTE.&id({IOSet}),
            //    values  SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{\@type})
            // }
            ASN1EncodableVector challpwdattr = new ASN1EncodableVector();
            // Challenge password attribute
            challpwdattr.add(PKCSObjectIdentifiers.pkcs_9_at_challengePassword); 
            ASN1EncodableVector pwdvalues = new ASN1EncodableVector();
            pwdvalues.add(new DERUTF8String(password));
            challpwdattr.add(new DERSet(pwdvalues));
            ASN1EncodableVector extensionattr = new ASN1EncodableVector();
            extensionattr.add(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            extensionattr.add(new DERSet(exts));
            // Complete the Attribute section of the request, the set (Attributes) contains two sequences (Attribute)
            ASN1EncodableVector v = new ASN1EncodableVector();
            v.add(new DERSequence(challpwdattr));
            v.add(new DERSequence(extensionattr));
            DERSet attributes = new DERSet(v);
            // Create PKCS#10 certificate request
            final PKCS10CertificationRequest p10request = CertTools.genPKCS10CertificationRequest("SHA1WithRSA",
                    CertTools.stringToBcX500Name(reqdn), keys.getPublic(), attributes, keys.getPrivate(), null);
            
            // wrap message in pkcs#7
            return wrap(p10request.getEncoded(), "19", transactionId, senderCertificate, signatureKey);
        }

        public byte[] generateGetCertInitial(String dn, String transactionId, X509Certificate ca, final X509Certificate senderCertificate,
                final PrivateKey signatureKey) throws NoSuchAlgorithmException,
                NoSuchProviderException, InvalidAlgorithmParameterException, CertStoreException, IOException, CMSException, CertificateEncodingException {
            this.cacert = ca;
            this.reqdn = dn;

            // pkcsGetCertInitial issuerAndSubject ::= { 
            //      issuer "the certificate authority issuer name" 
            //      subject "the requester subject name as given in PKCS#10" 
            //  } 
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new DERUTF8String(ca.getIssuerDN().getName()));
            vec.add(new DERUTF8String(dn));
            DERSequence seq = new DERSequence(vec);

            // wrap message in pkcs#7
            return wrap(seq.getEncoded(), "20", transactionId, senderCertificate, signatureKey);
        }
        
        private CMSEnvelopedData envelope(CMSTypedData envThis) throws CMSException, CertificateEncodingException {
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            // Envelope the CMS message
            edGen.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(cacert).setProvider(BouncyCastleProvider.PROVIDER_NAME));
            JceCMSContentEncryptorBuilder jceCMSContentEncryptorBuilder = new JceCMSContentEncryptorBuilder(SMIMECapability.dES_CBC).setProvider(BouncyCastleProvider.PROVIDER_NAME);
            CMSEnvelopedData ed = edGen.generate(envThis, jceCMSContentEncryptorBuilder.build());
            return ed;
        }

        private CMSSignedData sign(CMSTypedData signThis, String messageType, String transactionId, final X509Certificate senderCertificate,
                final PrivateKey signatureKey) throws CertificateEncodingException, CMSException {
            CMSSignedDataGenerator gen1 = new CMSSignedDataGenerator();

            // add authenticated attributes...status, transactionId, sender- and more...
            Hashtable<ASN1ObjectIdentifier, Attribute> attributes = new Hashtable<ASN1ObjectIdentifier, Attribute>();
            ASN1ObjectIdentifier oid;
            Attribute attr;
            DERSet value;
            
            // Message type (certreq)
            oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_messageType);
            value = new DERSet(new DERPrintableString(messageType));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            // TransactionId
            oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_transId);
            value = new DERSet(new DERPrintableString(transactionId));
            attr = new Attribute(oid, value);
            attributes.put(attr.getAttrType(), attr);

            // senderNonce
            byte[] nonce = new byte[16];
            randomSource.nextBytes(nonce);
            senderNonce = new String(Base64.encode(nonce));
            if (nonce != null) {
                oid = new ASN1ObjectIdentifier(ScepRequestMessage.id_senderNonce);
                log.debug("Added senderNonce: " + senderNonce);
                value = new DERSet(new DEROctetString(nonce));
                attr = new Attribute(oid, value);
                attributes.put(attr.getAttrType(), attr);
            }

            // Add our signer info and sign the message
            ArrayList<X509Certificate> certList = new ArrayList<X509Certificate>();
            certList.add(senderCertificate);
            gen1.addCertificates(new CollectionStore(CertTools.convertToX509CertificateHolder(certList)));
           
            String signatureAlgorithmName = AlgorithmTools.getAlgorithmNameFromDigestAndKey(digestOid, signatureKey.getAlgorithm());
            try {
                ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithmName).setProvider(signatureProvider).build(signatureKey);
                JcaDigestCalculatorProviderBuilder calculatorProviderBuilder = new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME);
                JcaSignerInfoGeneratorBuilder builder = new JcaSignerInfoGeneratorBuilder(calculatorProviderBuilder.build());
                builder.setSignedAttributeGenerator(new DefaultSignedAttributeTableGenerator(new AttributeTable(attributes)));
                gen1.addSignerInfoGenerator(builder.build(contentSigner, senderCertificate));
            } catch (OperatorCreationException e) {
                throw new IllegalStateException("BouncyCastle failed in creating signature provider.", e);
            }
            // The signed data to be enveloped
            CMSSignedData s = gen1.generate(signThis, true);
            return s;
        }

        private byte[] wrap(byte[] envBytes, String messageType, String transactionId, final X509Certificate senderCertificate,
                final PrivateKey signatureKey) throws CertificateEncodingException, CMSException, IOException {

            // 
            // Create inner enveloped data
            //
            CMSEnvelopedData ed = envelope(new CMSProcessableByteArray(envBytes));
            log.debug("Enveloped data is " + ed.getEncoded().length + " bytes long");
            CMSTypedData msg = new CMSProcessableByteArray(ed.getEncoded());
            //
            // Create the outer signed data
            //
            CMSSignedData s = sign(msg, messageType, transactionId, senderCertificate, signatureKey);

            byte[] ret = s.getEncoded();
            return ret;

        }
    }

}
