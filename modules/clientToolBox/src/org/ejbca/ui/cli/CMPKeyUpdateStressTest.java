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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509CertificateStructure;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.cmp.CMPSendHTTP;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;

import com.novosec.pkix.asn1.cmp.CMPObjectIdentifiers;
import com.novosec.pkix.asn1.cmp.CertOrEncCert;
import com.novosec.pkix.asn1.cmp.CertRepMessage;
import com.novosec.pkix.asn1.cmp.CertResponse;
import com.novosec.pkix.asn1.cmp.CertifiedKeyPair;
import com.novosec.pkix.asn1.cmp.PKIBody;
import com.novosec.pkix.asn1.cmp.PKIHeader;
import com.novosec.pkix.asn1.cmp.PKIMessage;
import com.novosec.pkix.asn1.cmp.PKIStatusInfo;
import com.novosec.pkix.asn1.crmf.AttributeTypeAndValue;
import com.novosec.pkix.asn1.crmf.CRMFObjectIdentifiers;
import com.novosec.pkix.asn1.crmf.CertReqMessages;
import com.novosec.pkix.asn1.crmf.CertReqMsg;
import com.novosec.pkix.asn1.crmf.CertRequest;
import com.novosec.pkix.asn1.crmf.CertTemplate;
import com.novosec.pkix.asn1.crmf.OptionalValidity;
import com.novosec.pkix.asn1.crmf.PBMParameter;
import com.novosec.pkix.asn1.crmf.POPOSigningKey;
import com.novosec.pkix.asn1.crmf.ProofOfPossession;

/**
 * Used to stress test the CMP interface.
 * @author primelars
 * @version $Id: CMPTest.java 11982 2011-05-16 13:36:33Z primelars $
 *
 */
class CMPKeyUpdateStressTest extends ClientToolBox {
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();
    static private class StressTest {
        final PerformanceTest performanceTest;

        final private PrivateKey oldKey;
        final private KeyPair newKeyPair;
        final private Certificate extraCert;
        final private X509Certificate cacert;
        final private CertificateFactory certificateFactory;
        final private Provider bcProvider = new BouncyCastleProvider();
        final private String hostName;
        final private int port;
        final private boolean isHttp;
        final String urlPath;
        final String resultCertFilePrefix;
        boolean isSign;
        boolean firstTime = true;
        //private int lastNextInt = 0;

        StressTest( final String _hostName,
                    final int _port,
                    final boolean _isHttp,
                    final InputStream certInputStream,
                    final int numberOfThreads,
                    final int waitTime,
                    final String _urlPath,
                    final String _resultCertFilePrefix,
                    final PrivateKey _oldKey,
                    final Certificate _extraCert) throws Exception {

            this.hostName = _hostName;
            this.certificateFactory = CertificateFactory.getInstance("X.509", this.bcProvider);
            this.cacert = (X509Certificate)this.certificateFactory.generateCertificate(certInputStream);
            this.port = _port;
            this.isHttp = _isHttp;
            this.urlPath = _urlPath;
            this.resultCertFilePrefix = _resultCertFilePrefix;

            final KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
            keygen.initialize(2048);
            this.newKeyPair = keygen.generateKeyPair();
            this.oldKey = _oldKey;
            this.extraCert = _extraCert;
            
            this.performanceTest = new PerformanceTest();
            this.performanceTest.execute(new MyCommandFactory(), numberOfThreads, waitTime, System.out);
        }
        
        private CertRequest genKeyUpdateReq() throws IOException {
            final OptionalValidity myOptionalValidity = new OptionalValidity();
            final int day = 1000*60*60*24;
            myOptionalValidity.setNotBefore( new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime()-day)) );
            myOptionalValidity.setNotAfter( new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime()+10*day)) );

            final CertTemplate myCertTemplate = new CertTemplate();
            myCertTemplate.setValidity( myOptionalValidity );
            final byte[]                  bytes = this.newKeyPair.getPublic().getEncoded();
            final ByteArrayInputStream    bIn = new ByteArrayInputStream(bytes);
            final ASN1InputStream         dIn = new ASN1InputStream(bIn);
            final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence)dIn.readObject());
            myCertTemplate.setPublicKey(keyInfo);
            return new CertRequest(new DERInteger(4), myCertTemplate);
        }
        private PKIMessage genPKIMessage(final SessionData sessionData,
                                      final boolean raVerifiedPopo,
                                      final CertRequest keyUpdateRequest) throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {

            final CertReqMsg myCertReqMsg = new CertReqMsg(keyUpdateRequest);

            ProofOfPossession myProofOfPossession;
            if (raVerifiedPopo) {
                // raVerified POPO (meaning there is no POPO)
                myProofOfPossession = new ProofOfPossession(new DERNull(), 0);
            } else {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final DEROutputStream mout = new DEROutputStream( baos );
                mout.writeObject( keyUpdateRequest );
                mout.close();
                final byte[] popoProtectionBytes = baos.toByteArray();
                final Signature sig = Signature.getInstance( PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                sig.initSign(this.oldKey);
                sig.update( popoProtectionBytes );

                final DERBitString bs = new DERBitString(sig.sign());

                final POPOSigningKey myPOPOSigningKey =
                    new POPOSigningKey(
                            new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption),
                            bs);
                //myPOPOSigningKey.setPoposkInput( myPOPOSigningKeyInput );
                myProofOfPossession = new ProofOfPossession(myPOPOSigningKey, 1);           
            }

            myCertReqMsg.setPop(myProofOfPossession);

            final AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.regCtrl_regToken, new DERUTF8String("foo123")); 
            myCertReqMsg.addRegInfo(av);

            final CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

            final PKIHeader myPKIHeader =
                new PKIHeader( new DERInteger(2),
                               new GeneralName(new X509Name(CertTools.getSubjectDN(extraCert))),
                               new GeneralName(new X509Name(this.cacert.getSubjectDN().getName())) );
            myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
            myPKIHeader.setSenderNonce(new DEROctetString(sessionData.getNonce()));
            myPKIHeader.setTransactionID(new DEROctetString(sessionData.getTransId()));

            final PKIBody myPKIBody = new PKIBody(myCertReqMessages, 7); // key update request
            return new PKIMessage(myPKIHeader, myPKIBody);   
        }
        
        private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
            ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
            ASN1InputStream         dIn = new ASN1InputStream(bIn);
            ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
            X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
            msg.addExtraCert(extraCert);
        }
        
        private PKIMessage signPKIMessage(final PKIMessage msg, PrivateKey signingKey) throws NoSuchAlgorithmException, NoSuchProviderException, 
                                InvalidKeyException, SignatureException {
            PKIMessage message = msg;
            final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
            sig.initSign(signingKey);
            sig.update(message.getProtectedBytes());
            byte[] eeSignature = sig.sign();            
            message.setProtection(new DERBitString(eeSignature));
            return message;
        }
        
        private byte[] sendCmpHttp(final byte[] message) throws Exception {
            final CMPSendHTTP send = CMPSendHTTP.doIt(message, StressTest.this.hostName, StressTest.this.port, StressTest.this.urlPath, false);
            if ( send.responseCode!=HttpURLConnection.HTTP_OK ) {
                StressTest.this.performanceTest.getLog().error(intres.getLocalizedMessage("cmp.responsecodenotok", Integer.valueOf(send.responseCode)));
                return null;
            }
            if ( send.contentType==null ) {
                StressTest.this.performanceTest.getLog().error("No content type received.");
                return null;
            }
            // Some appserver (Weblogic) responds with "application/pkixcmp; charset=UTF-8"
            if ( !send.contentType.startsWith("application/pkixcmp") ) {
                StressTest.this.performanceTest.getLog().info("wrong content type: "+send.contentType);
            }
            return send.response;
        }
        private boolean checkCmpResponseGeneral(final byte[] retMsg,
                                                final SessionData sessionData,
                                                final boolean requireProtection) throws Exception {
            //
            // Parse response message
            //
            final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
            if ( respObject==null ) {
                StressTest.this.performanceTest.getLog().error("No command response message.");
                return false;
            }
            
            // The signer, i.e. the CA, check it's the right CA
            final PKIHeader header = respObject.getHeader();
            if ( header==null ) {
                StressTest.this.performanceTest.getLog().error("No header in response message.");
                return false;
            }
            // Check that the signer is the expected CA
            final X509Name name = X509Name.getInstance(header.getSender().getName()); 
            if ( header.getSender().getTagNo()!=4 || name==null || !name.equals(this.cacert.getSubjectDN()) ) {
                StressTest.this.performanceTest.getLog().error("Not signed by right issuer.");
            }

            if ( header.getSenderNonce().getOctets().length!=16 ) {
                StressTest.this.performanceTest.getLog().error("Wrong length of received sender nonce (made up by server). Is "+header.getSenderNonce().getOctets().length+" byte but should be 16.");
            }

            if ( !Arrays.equals(header.getRecipNonce().getOctets(), sessionData.getNonce()) ) {
                StressTest.this.performanceTest.getLog().error("recipient nonce not the same as we sent away as the sender nonce. Sent: "+Arrays.toString(sessionData.getNonce())+" Received: "+Arrays.toString(header.getRecipNonce().getOctets()));
            }

            if ( !Arrays.equals(header.getTransactionID().getOctets(), sessionData.getTransId()) ) {
                StressTest.this.performanceTest.getLog().error("transid is not the same as the one we sent");
            }
            {
                // Check that the message is signed with the correct digest alg
                final AlgorithmIdentifier algId = header.getProtectionAlg();
                if (algId==null || algId.getObjectId()==null || algId.getObjectId().getId()==null) {
                    if ( requireProtection ) {
                        StressTest.this.performanceTest.getLog().error("Not possible to get algorithm.");
                        return false;
                    }
                    return true;
                }
                final String id = algId.getObjectId().getId();
                if ( id.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId()) ) {
                    if ( this.firstTime ) {
                        this.firstTime = false;
                        this.isSign = true;
                        StressTest.this.performanceTest.getLog().info("Signature protection used.");
                    } else if ( !this.isSign ) {
                        StressTest.this.performanceTest.getLog().error("Message password protected but should be signature protected.");
                    }
                } else if ( id.equals(CMPObjectIdentifiers.passwordBasedMac.getId()) ) {
                    if ( this.firstTime ) {
                        this.firstTime = false;
                        this.isSign = false;
                        StressTest.this.performanceTest.getLog().info("Password (PBE) protection used.");
                    } else if ( this.isSign ) {
                        StressTest.this.performanceTest.getLog().error("Message signature protected but should be password protected.");
                    }
                } else {
                    StressTest.this.performanceTest.getLog().error("No valid algorithm.");
                    return false;
                }
            }
            if ( this.isSign ) {
                // Verify the signature
                byte[] protBytes = respObject.getProtectedBytes();
                final DERBitString bs = respObject.getProtection();
                final Signature sig;
                try {
                    sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                    sig.initVerify(this.cacert);
                    sig.update(protBytes);
                    if ( !sig.verify(bs.getBytes()) ) {
                        StressTest.this.performanceTest.getLog().error("CA signature not verifying");
                    }
                } catch ( Exception e) {
                    StressTest.this.performanceTest.getLog().error("Not possible to verify signature.", e);
                }           
            } else {
                //final DEROctetString os = header.getSenderKID();
                //if ( os!=null )
                //    StressTest.this.performanceTest.getLog().info("Found a sender keyId: "+new String(os.getOctets()));
                // Verify the PasswordBased protection of the message
                final PBMParameter pp; {
                    final AlgorithmIdentifier pAlg = header.getProtectionAlg();
                    // StressTest.this.performanceTest.getLog().info("Protection type is: "+pAlg.getObjectId().getId());
                    pp = PBMParameter.getInstance(pAlg.getParameters());
                }
                final int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
                // StressTest.this.performanceTest.getLog().info("Iteration count is: "+iterationCount);
                final AlgorithmIdentifier owfAlg = pp.getOwf();
                // Normal OWF alg is 1.3.14.3.2.26 - SHA1
                // StressTest.this.performanceTest.getLog().info("Owf type is: "+owfAlg.getObjectId().getId());
                final AlgorithmIdentifier macAlg = pp.getMac();
                // Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
                // StressTest.this.performanceTest.getLog().info("Mac type is: "+macAlg.getObjectId().getId());
                final byte[] salt = pp.getSalt().getOctets();
                //log.info("Salt is: "+new String(salt));
                final byte[] raSecret = new String("password").getBytes();
                // HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7 
                final String macOid = macAlg.getObjectId().getId();
                final SecretKey key; {
                    byte[] basekey = new byte[raSecret.length + salt.length];
                    for (int i = 0; i < raSecret.length; i++) {
                        basekey[i] = raSecret[i];
                    }
                    for (int i = 0; i < salt.length; i++) {
                        basekey[raSecret.length+i] = salt[i];
                    }
                    // Construct the base key according to rfc4210, section 5.1.3.1
                    final MessageDigest dig = MessageDigest.getInstance(owfAlg.getObjectId().getId(), this.bcProvider);
                    for (int i = 0; i < iterationCount; i++) {
                        basekey = dig.digest(basekey);
                        dig.reset();
                    }
                    key = new SecretKeySpec(basekey, macOid);
                }
                final Mac mac = Mac.getInstance(macOid, this.bcProvider);
                mac.init(key);
                mac.reset();
                final byte[] protectedBytes = respObject.getProtectedBytes();
                final DERBitString protection = respObject.getProtection();
                mac.update(protectedBytes, 0, protectedBytes.length);
                byte[] out = mac.doFinal();
                // My out should now be the same as the protection bits
                byte[] pb = protection.getBytes();
                if ( !Arrays.equals(out, pb) ) {
                    StressTest.this.performanceTest.getLog().error("Wrong PBE hash");
                }
            }
            return true;
        }
        private X509Certificate checkCmpCertRepMessage(final SessionData sessionData,
                                                       final byte[] retMsg,
                                                       final int requestId) throws IOException, CertificateException {
            //
            // Parse response message
            //
            final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
            if ( respObject==null ) {
                StressTest.this.performanceTest.getLog().error("No PKIMessage for certificate received.");
                return null;
            }
            final PKIBody body = respObject.getBody();
            if ( body==null ) {
                StressTest.this.performanceTest.getLog().error("No PKIBody for certificate received.");
                return null;
            }
            if ( body.getTagNo()!=8 ) {
                StressTest.this.performanceTest.getLog().error("Cert body tag not 8.");
                return null;
            }
            final CertRepMessage c = body.getKup();
            if ( c==null ) {
                StressTest.this.performanceTest.getLog().error("No CertRepMessage for certificate received.");
                return null;
            }
            final CertResponse resp = c.getResponse(0);
            if ( resp==null ) {
                StressTest.this.performanceTest.getLog().error("No CertResponse for certificate received.");
                return null;
            }
            if ( resp.getCertReqId().getValue().intValue()!=requestId ) {
                StressTest.this.performanceTest.getLog().error("Received CertReqId is "+resp.getCertReqId().getValue().intValue()+" but should be "+requestId);
                return null;
            }
            final PKIStatusInfo info = resp.getStatus();
            if ( info==null ) {
                StressTest.this.performanceTest.getLog().error("No PKIStatusInfo for certificate received.");
                return null;
            }
            if ( info.getStatus().getValue().intValue()!=0 ) {
                StressTest.this.performanceTest.getLog().error("Received Status is "+info.getStatus().getValue().intValue()+" but should be 0");
                return null;
            }
            final CertifiedKeyPair kp = resp.getCertifiedKeyPair();
            if ( kp==null ) {
                StressTest.this.performanceTest.getLog().error("No CertifiedKeyPair for certificate received.");
                return null;
            }
            final CertOrEncCert cc = kp.getCertOrEncCert();
            if ( cc==null ) {
                StressTest.this.performanceTest.getLog().error("No CertOrEncCert for certificate received.");
                return null;
            }
            final X509CertificateStructure struct = cc.getCertificate();
            if ( struct==null ) {
                StressTest.this.performanceTest.getLog().error("No X509CertificateStructure for certificate received.");
                return null;
            }
            final byte encoded[] = struct.getEncoded();
            if ( encoded==null || encoded.length<=0 ) {
                StressTest.this.performanceTest.getLog().error("No encoded certificate received.");
                return null;
            }
            final X509Certificate cert = (X509Certificate)this.certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
            if ( cert==null ) {
                StressTest.this.performanceTest.getLog().error("Not possbile to create certificate.");
                return null;
            }
            // Remove this test to be able to test unid-fnr
            if ( cert.getSubjectDN().hashCode() != new X509Name(CertTools.getSubjectDN(extraCert)).hashCode() ) {
                StressTest.this.performanceTest.getLog().error("Subject is '"+cert.getSubjectDN()+"' but should be '"+CertTools.getSubjectDN(extraCert)+'\'');
                return null;
            }
            if ( cert.getIssuerX500Principal().hashCode() != this.cacert.getSubjectX500Principal().hashCode() ) {
                StressTest.this.performanceTest.getLog().error("Issuer is '"+cert.getIssuerDN()+"' but should be '"+this.cacert.getSubjectDN()+'\'');
                return null;
            }
            try {
                cert.verify(this.cacert.getPublicKey());
            } catch (Exception e) {
                StressTest.this.performanceTest.getLog().error("Certificate not verifying. See exception", e);
                return null;
            }
            return cert;
        }

        private class GetCertificate implements Command {
            final private SessionData sessionData;
            GetCertificate(final SessionData sd) {
                this.sessionData = sd;                
            }

            public boolean doIt() throws Exception {
                this.sessionData.newSession();
                
                CertRequest keyUpdateReq = genKeyUpdateReq();
                PKIMessage certMsg = genPKIMessage(this.sessionData, true, keyUpdateReq);
                if ( certMsg==null ) {
                    StressTest.this.performanceTest.getLog().error("No certificate request.");
                    return false;
                }
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                certMsg.getHeader().setProtectionAlg(pAlg);
                //certMsg.getHeader().setSenderKID(new DEROctetString("EMPTY".getBytes()));
                PKIMessage signedMsg = signPKIMessage(certMsg, oldKey);
                addExtraCert(signedMsg, extraCert);
                if ( signedMsg==null ) {
                    StressTest.this.performanceTest.getLog().error("No protected message.");
                    return false;
                }
                
                
                this.sessionData.setReqId(signedMsg.getBody().getKur().getCertReqMsg(0).getCertReq().getCertReqId().getValue().intValue());
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(signedMsg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba);
                if ( resp==null || resp.length <= 0 ) {
                    StressTest.this.performanceTest.getLog().error("No response message.");
                    return false;
                }
                if ( !checkCmpResponseGeneral(resp, this.sessionData, true) ) {
                    return false;
                }
                final X509Certificate cert = checkCmpCertRepMessage(this.sessionData, resp, this.sessionData.getReqId());
                if ( cert==null ) {
                    return false;
                }
                final BigInteger serialNumber = CertTools.getSerialNumber(cert);
                if ( StressTest.this.resultCertFilePrefix!=null ) {
                    new FileOutputStream(StressTest.this.resultCertFilePrefix+serialNumber+".dat").write(cert.getEncoded());
                }
                StressTest.this.performanceTest.getLog().result(serialNumber);

                return true;
            }
            public String getJobTimeDescription() {
                return "Get certificate";
            }
            /*
            private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException{
                ByteArrayInputStream    bIn = new ByteArrayInputStream(cert.getEncoded());
                ASN1InputStream         dIn = new ASN1InputStream(bIn);
                ASN1Sequence extraCertSeq = (ASN1Sequence)dIn.readObject();
                X509CertificateStructure extraCert = new X509CertificateStructure(ASN1Sequence.getInstance(extraCertSeq));
                msg.addExtraCert(extraCert);
            }
            */
        }        
        
        class SessionData {
            final private byte[] nonce = new byte[16];
            final private byte[] transid = new byte[16];
//            private int lastNextInt = 0;
            //private String userDN;
            private int reqId;
            //Socket socket;
            //final private static int howOftenToGenerateSameUsername = 3;  // 0 = never, 1 = 100% chance, 2=50% chance etc.. 
            SessionData() {
                super();
            }
            /*
            Socket getSocket() throws UnknownHostException, IOException {
                if ( StressTest.this.isHttp ) {
                    return null;
                }
                if ( this.socket==null || this.socket.isClosed() || !this.socket.isBound() || !this.socket.isConnected() || this.socket.isInputShutdown() || this.socket.isOutputShutdown() ) {
                    StressTest.this.performanceTest.getLog().info("New socket created for thread with '"+this.transid+"'.");
                    this.socket = new Socket(StressTest.this.hostName, StressTest.this.port);
                    this.socket.setKeepAlive(true);
                }
                return this.socket;
            }
            */
            /*
            private String getRandomAllDigitString( int length ) {
                final String s = Integer.toString( StressTest.this.performanceTest.getRandom().nextInt() );
                return s.substring(s.length()-length);
            }
            private String getFnrLra() {
                return getRandomAllDigitString(6)+getRandomAllDigitString(5)+'-'+getRandomAllDigitString(5);
            }
            private int getRandomAndRepeated() {
                // Initialize with some new value every time the test is started
                // Return the same value once in a while so we have multiple requests for the same username
                if ( this.lastNextInt==0 || howOftenToGenerateSameUsername==0 || StressTest.this.performanceTest.getRandom().nextInt()%howOftenToGenerateSameUsername!=0 ) {
                    this.lastNextInt = StressTest.this.performanceTest.getRandom().nextInt();
                }
                return this.lastNextInt;
            }
            */
            void newSession() {
                //this.userDN = "CN=CMP Test User Nr "+getRandomAndRepeated()+",serialNumber="+getFnrLra();
                StressTest.this.performanceTest.getRandom().nextBytes(this.nonce);
                StressTest.this.performanceTest.getRandom().nextBytes(this.transid);
            }
            int getReqId() {
                return this.reqId;
            }
            void setReqId(int i) {
                this.reqId = i;
            }
            /*
            String getUserDN() {
                return this.userDN;
            }
            */
            byte[] getTransId() {
                return this.transid;
            }
            byte[] getNonce() {
                return this.nonce;
            }
        }
        private class MyCommandFactory implements CommandFactory {
            public Command[] getCommands() throws Exception {
                final SessionData sessionData = new SessionData();
                return new Command[]{new GetCertificate(sessionData)};//, new Revoke(sessionData)};
            }
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#execute(java.lang.String[])
     */
    @Override
    protected void execute(String[] args) {
        final String hostName;
        final String keystoreFile;
        final String keystorePassword;
        final String certNameInKeystore;
        final int numberOfThreads;
        final int waitTime;
        final String certFileName;
        final File certFile;
        final String keyId;
        final int port;
//        final boolean isHttp;
        final String urlPath;
        final String resultFilePrefix;
        if ( args.length < 6 ) {
            System.out.println(args[0]+" <host name> <CA certificate file name> <keystore (p12)> <keystore password> <friendlyname in keystore> [<number of threads>] [<wait time (ms) between each thread is started>] [<port>] [<URL path of servlet. use 'null' to get EJBCA (not proxy) default>] [<certificate file prefix. set this if you want all received certificates stored on files>]");
            System.out.println("EJBCA build configutation requirements: cmp.operationmode=normal, cmp.allowraverifypopo=true, cmp.allowautomatickeyupdate=true, cmp.allowupdatewithsamekey=true");
//            System.out.println("EJBCA build configuration optional: cmp.ra.certificateprofile=KeyId cmp.ra.endentityprofile=KeyId (used when the KeyId argument should be used as profile name).");
            System.out.println("Ejbca expects the following: There exists an end entity with a generated certificate. The end entity's certificate and its private key are stored in the keystore used " +
            		"in the commandline. The end entity's certificate's 'friendly name' in the keystore is the one used in the command line. Such keystor can be obtained, for example, by specifying " +
            		"the token to be 'P12' when creating the end entity and then download the keystore by choosing 'create keystore' from the public web");
            return;
        }
        hostName = args[1];
        certFileName = args[2];
        certFile = new File(certFileName);
        keystoreFile = args[3];
        keystorePassword = args[4];
        certNameInKeystore = args[5];
        numberOfThreads = args.length>6 ? Integer.parseInt(args[6].trim()):1;
        waitTime = args.length>7 ? Integer.parseInt(args[7].trim()):0;
        port = args.length>8 ? Integer.parseInt(args[8].trim()):8080;
//        isHttp = true;
        urlPath = args.length>9 && args[9].toLowerCase().indexOf("null")<0 ? args[9].trim():null;
        resultFilePrefix = args.length>10 ? args[10].trim() : null;

        CryptoProviderTools.installBCProviderIfNotAvailable();
        
        
        Certificate extracert = null;
        PrivateKey oldCertKey = null;
        
        FileInputStream file_inputstream;
        try {
            file_inputstream = new FileInputStream(keystoreFile);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(file_inputstream, keystorePassword.toCharArray());
            /*
            Enumeration aliases = keyStore.aliases();
            while(aliases.hasMoreElements()) {
                System.out.println(aliases.nextElement());
            }
            */
            Key key=keyStore.getKey(certNameInKeystore, keystorePassword.toCharArray());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            oldCertKey = keyFactory.generatePrivate(keySpec);
            extracert = keyStore.getCertificate(certNameInKeystore);
        } catch (FileNotFoundException e2) {
            e2.printStackTrace();
            System.exit(-1);
        } catch (KeyStoreException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (CertificateException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
            System.exit(-1);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        
        try {
            if ( !certFile.canRead() ) {
                System.out.println("File "+certFile.getCanonicalPath()+" not a valid file name.");
                return;
            }
//            Security.addProvider(new BouncyCastleProvider());
            new StressTest(hostName, port, true, new FileInputStream(certFile), numberOfThreads, waitTime, urlPath, resultFilePrefix, oldCertKey, extracert);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /* (non-Javadoc)
     * @see org.ejbca.ui.cli.ClientToolBox#getName()
     */
    @Override
    protected String getName() {
        return "CMPKeyUpdateStressTest";
    }

}
