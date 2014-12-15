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
import java.security.cert.CertStoreException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Random;

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
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
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.util.Store;
import org.bouncycastle.util.encoders.Base64;
import org.cesecore.certificates.certificate.request.ResponseStatus;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.scep.ScepRequestGenerator;
import org.ejbca.core.protocol.scep.ScepRequestMessage;
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
        final private String url;
        
        final private KeyPair keyPair;

        private final Random random = new Random();
        private final String caName;

        StressTest( final String url,
                    final int numberOfThreads,
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
            this.performanceTest.execute(new MyCommandFactory(userCNBase), numberOfThreads, waitTime, System.out);
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
                final Store certstore = s.getCertificates();
                @SuppressWarnings("unchecked")
                final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
                // Length two if the Scep RA server is signed directly by a Root CA
                // Length three if the Scep RA server is signed by a CA which is signed by a Root CA
                final Iterator<X509CertificateHolder> it = certs.iterator();
                if ( this.sessionData.certchain!=null && this.sessionData.certchain.length!=certs.size() ) {
                    StressTest.this.performanceTest.getLog().error("Length of received certificate chain "+certs.size()+" but should be "+this.sessionData.certchain.length);
                    return false;
                }
                JcaX509CertificateConverter jcaX509CertificateConverter = new JcaX509CertificateConverter();
                final X509Certificate tmp[] = new X509Certificate[certs.size()];
                for (int i=0; it.hasNext(); i++ ) {
                    tmp[i] = jcaX509CertificateConverter.getCertificate(it.next());
                    if ( this.sessionData.certchain==null ) {
                        StressTest.this.performanceTest.getLog().info("Cert "+i+" "+tmp[i].getSubjectDN());
                    } else if ( !tmp[i].equals(this.sessionData.certchain[i]) ) {
                        StressTest.this.performanceTest.getLog().error("New cert chain is not equal to old!");
                        return false;
                    }
                }
                this.sessionData.certchain = tmp;
                return true;
            }
            public String getJobTimeDescription() {
                return "Get certificate chain";
            }
        }
        private Extensions generateExtensions(int bcKeyUsage) throws IOException {
            // Extension request attribute is a set of X509Extensions
            // ASN1EncodableVector x509extensions = new ASN1EncodableVector();
            // An X509Extensions is a sequence of Extension which is a sequence of {oid, X509Extension}
            ExtensionsGenerator extgen = new ExtensionsGenerator();
            { // KeyUsage
                final X509KeyUsage ku = new X509KeyUsage(bcKeyUsage);
                final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                final DEROutputStream dOut = new DEROutputStream(bOut);
                dOut.writeObject(ku);
                final byte value[] = bOut.toByteArray();
                extgen.addExtension(Extension.keyUsage, false, new DEROctetString(value));
            }
            {// Requested extensions attribute
                // AltNames
                GeneralNames san = CertTools.getGeneralNamesFromAltName("dNSName=foo.bar.com,iPAddress=10.0.0.1");
                ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                DEROutputStream dOut = new DEROutputStream(bOut);
                dOut.writeObject(san);
                extgen.addExtension(Extension.subjectAlternativeName, false, new DEROctetString(bOut.toByteArray()));
            }
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
                gen.setKeys(StressTest.this.keyPair);
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
                        msgBytes = gen.generateCertReq(userDN, "foo123", transactionId, this.sessionData.certchain[0], generateExtensions(bcKeyUsage));                    
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
                    gen.setKeys(StressTest.this.keyPair);
                    gen.setDigestOid(CMSSignedGenerator.DIGEST_SHA1);
                    final byte[] msgBytes = gen.generateGetCertInitial(userDN, transactionId, this.sessionData.certchain[0]);                    
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
             * 
             */
            private boolean checkScepResponse(byte[] retMsg, String senderNonce, String transId, boolean crlRep, String digestOid, boolean noca, ResponseStatus expectedResponseStatus, String userDN, boolean[] keyUsage) throws CMSException, NoSuchProviderException, NoSuchAlgorithmException, CertStoreException, InvalidKeyException, CertificateException, SignatureException, CRLException, IOException {
            	//
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
            	boolean ret = signerInfo.verify(this.sessionData.certchain[0].getPublicKey(), "BC");
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
            	final byte decBytes[] = recipient.getContent(StressTest.this.keyPair.getPrivate(), "BC");
            	// This is yet another CMS signed data
            	final CMSSignedData sd = new CMSSignedData(decBytes);
            	// Get certificates from the signed data
            	final Store certstore = sd.getCertificates();
            	if (crlRep) {
            		// We got a reply with a requested CRL
            		@SuppressWarnings("unchecked")
                    final Collection<X509CRLHolder> crls = sd.getCRLs().getMatches(null);
            		if ( crls.size() != 1 ) {
            			StressTest.this.performanceTest.getLog().error("CRLS should be 1: "+crls.size());
            			return false;
            		}
            		final Iterator<?> it = crls.iterator();
            		// CRL is first (and only)
            		final X509CRL retCrl = (X509CRL)it.next();
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
                final Collection<X509CertificateHolder> certs = certstore.getMatches(null);
            	//System.out.println("Got certificate reply with certchain of length: "+certs.size());
            	// EJBCA returns the issued cert and the CA cert (cisco vpn client requires that the ca cert is included)
            	final X509Certificate usercert;
            	final X509Certificate cacert;
            	if (noca) {
            		if ( certs.size() != 1 ) {
            			StressTest.this.performanceTest.getLog().error("Certs should be 1: "+certs.size());
            			return false;
            		}
            		final Iterator<?> it = certs.iterator();
            		usercert = (X509Certificate)it.next();
            		cacert = null;
            	} else {
            		if ( certs.size() != 2 ) {
            			StressTest.this.performanceTest.getLog().error("Certs should be 2: "+certs.size());
            			return false;
            		}
            		final Iterator<?> it = certs.iterator();
            		usercert = (X509Certificate)it.next();
            		cacert = (X509Certificate)it.next();
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
            	if ( !StringUtils.equals("iPAddress=10.0.0.1, dNSName=foo.bar.com", altName) ) {
            		StressTest.this.performanceTest.getLog().error("altName should be iPAddress=10.0.0.1, dNSName=foo.bar.com but was: "+altName);
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
        final int numberOfThreads;
        final int waitTime;
        final String caName;
        final String userCNBase;
        if ( args.length < 3 ) {
            System.out.println(args[0]+" <SCEP url> <CA name> [<number of threads>] [<wait time between each thread is started>] [<user CN to be prepended by >]");
            System.out.println("SCEP URL extra example: http://127.0.0.1:8080/scepraserver/scep/pkiclient.exe");
            System.out.println("SCEP URL ca example: http://localhost:8080/ejbca/publicweb/apply/scep/noca/pkiclient.exe");
            System.out.println();
            System.out.println("NOTE: This test should work for both EJBCA and EXTRA.");
            System.out.println("Originally it was written for EXTRA. But then it was change to use EJBCA directly also.");
            System.out.println("After the change it has not been verified that it is still working with EXTRA.");
            System.out.println("If you got problems with EXTRA you may revert back to the old version which is 8099 in SVN");
            return;
        }
        url = args[1];
        caName = args[2];
        numberOfThreads = args.length>3 ? Integer.parseInt(args[3].trim()):1;
        waitTime = args.length>4 ? Integer.parseInt(args[4].trim()):0;
        userCNBase = args.length>5 ? args[5] : null;

        try {
            new StressTest(url, numberOfThreads, waitTime, caName, userCNBase);
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

}
