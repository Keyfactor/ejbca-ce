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
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
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

import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DEROutputStream;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.CMPCertificate;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.cmp.CertConfirmContent;
import org.bouncycastle.asn1.cmp.CertOrEncCert;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.CertResponse;
import org.bouncycastle.asn1.cmp.CertStatus;
import org.bouncycastle.asn1.cmp.CertifiedKeyPair;
import org.bouncycastle.asn1.cmp.PBMParameter;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CRMFObjectIdentifiers;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.crmf.POPOSigningKey;
import org.bouncycastle.asn1.crmf.ProofOfPossession;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.cesecore.internal.InternalResources;
import org.cesecore.util.CertTools;
import org.cesecore.util.CryptoProviderTools;
import org.ejbca.core.protocol.cmp.CMPSendHTTP;
import org.ejbca.core.protocol.cmp.CmpMessageHelper;
import org.ejbca.util.PerformanceTest;
import org.ejbca.util.PerformanceTest.Command;
import org.ejbca.util.PerformanceTest.CommandFactory;


/**
 * Used to stress test the CMP interface.
 * @version $Id$
 */
public class CMPKeyUpdateStressTest extends ClientToolBox {
    /** Internal localization of logs and errors */
    private static final InternalResources intres = InternalResources.getInstance();

    private static class StressTest {
        private final PerformanceTest performanceTest;

        private final PrivateKey oldKey;
        private final KeyPair newKeyPair;
        private final Certificate extraCert;
        private final X509Certificate cacert;
        private final String eepassword;
        private final CertificateFactory certificateFactory;
        private final Provider bcProvider = new BouncyCastleProvider();
        private final String hostName;
        private final int port;
        private final String urlPath;
        private final String resultCertFilePrefix;
        private boolean isSign;
        private boolean firstTime = true;

        public StressTest(final String _hostName, final int _port, final int numberOfThreads, final int waitTime, final String _urlPath,
                final String _resultCertFilePrefix, final String _eepassword, final X509Certificate _cacert, final PrivateKey _oldKey,
                final Certificate _extraCert) throws Exception {

            this.hostName = _hostName;
            this.certificateFactory = CertificateFactory.getInstance("X.509", this.bcProvider);
            this.cacert = _cacert;
            this.eepassword = _eepassword;
            this.port = _port;
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
            ASN1EncodableVector optionalValidityV = new ASN1EncodableVector();
            final int day = 1000 * 60 * 60 * 24;
            optionalValidityV.add(new DERTaggedObject(true, 0, new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime() - day))));
            optionalValidityV.add(new DERTaggedObject(true, 1, new org.bouncycastle.asn1.x509.Time(new Date(new Date().getTime() + 10 * day))));
            OptionalValidity myOptionalValidity = OptionalValidity.getInstance(new DERSequence(optionalValidityV));

            final CertTemplateBuilder myCertTemplate = new CertTemplateBuilder();
            myCertTemplate.setValidity(myOptionalValidity);
            final byte[] bytes = this.newKeyPair.getPublic().getEncoded();
            final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
            final ASN1InputStream dIn = new ASN1InputStream(bIn);
            final SubjectPublicKeyInfo keyInfo = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());
            dIn.close();
            myCertTemplate.setPublicKey(keyInfo);
            return new CertRequest(4, myCertTemplate.build(), null);
        }

        private PKIMessage genPKIMessage(final SessionData sessionData, final boolean raVerifiedPopo, 
                final CertRequest keyUpdateRequest, final AlgorithmIdentifier pAlg, final DEROctetString senderKID)
                throws NoSuchAlgorithmException, IOException, InvalidKeyException, SignatureException {

            ProofOfPossession myProofOfPossession;
            if (raVerifiedPopo) {
                // raVerified POPO (meaning there is no POPO)
                myProofOfPossession = new ProofOfPossession();
            } else {
                final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                final DEROutputStream mout = new DEROutputStream(baos);
                mout.writeObject(keyUpdateRequest);
                mout.close();
                final byte[] popoProtectionBytes = baos.toByteArray();
                final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                sig.initSign(this.oldKey);
                sig.update(popoProtectionBytes);

                final DERBitString bs = new DERBitString(sig.sign());

                final POPOSigningKey myPOPOSigningKey = new POPOSigningKey(null, new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption), bs);
                myProofOfPossession = new ProofOfPossession(myPOPOSigningKey);
            }

            final AttributeTypeAndValue av = new AttributeTypeAndValue(CRMFObjectIdentifiers.id_regCtrl_regToken, new DERUTF8String("foo123"));
            AttributeTypeAndValue[] avs = {av};

            final CertReqMsg myCertReqMsg = new CertReqMsg(keyUpdateRequest, myProofOfPossession, avs);
            
            final CertReqMessages myCertReqMessages = new CertReqMessages(myCertReqMsg);

            final PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(CertTools.getSubjectDN(extraCert))),
                    new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
            myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
            myPKIHeader.setSenderNonce(new DEROctetString(sessionData.getNonce()));
            myPKIHeader.setSenderKID(new DEROctetString(sessionData.getNonce()));
            myPKIHeader.setTransactionID(new DEROctetString(sessionData.getTransId()));
            myPKIHeader.setProtectionAlg(pAlg);
            myPKIHeader.setSenderKID(senderKID);

            final PKIBody myPKIBody = new PKIBody(7, myCertReqMessages); // key update request
            return new PKIMessage(myPKIHeader.build(), myPKIBody);
        }

        private void addExtraCert(PKIMessage msg, Certificate cert) throws CertificateEncodingException, IOException {
            ASN1InputStream ins = new ASN1InputStream(cert.getEncoded());
            ASN1Primitive pcert = ins.readObject();
            CMPCertificate cmpcert = new CMPCertificate(new AttributeCertificate((ASN1Sequence) pcert));
            CMPCertificate[] extraCerts = {cmpcert};
            msg = new PKIMessage(msg.getHeader(), msg.getBody(), msg.getProtection(), extraCerts);
        }

        private PKIMessage signPKIMessage(final PKIMessage msg, PrivateKey signingKey) throws NoSuchAlgorithmException, NoSuchProviderException,
                InvalidKeyException, SignatureException {
            PKIMessage message = msg;
            final Signature sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), "BC");
            sig.initSign(signingKey);
            sig.update(CmpMessageHelper.getProtectedBytes(message));
            byte[] eeSignature = sig.sign();
            message = new PKIMessage(msg.getHeader(), msg.getBody(), new DERBitString(eeSignature), msg.getExtraCerts());
            return message;
        }

        private PKIMessage protectPKIMessage(final PKIMessage msg, final boolean badObjectId, final String password) throws NoSuchAlgorithmException,
                InvalidKeyException {
            // SHA1
            final AlgorithmIdentifier owfAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.3.14.3.2.26"));
            // 567 iterations
            final int iterationCount = 567;
            // HMAC/SHA1
            final AlgorithmIdentifier macAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.2.7"));
            final byte[] salt = "foo123".getBytes();
            final DEROctetString derSalt = new DEROctetString(salt);
            
            // Create the PasswordBased protection of the message
            final PKIHeaderBuilder head = getHeaderBuilder(msg.getHeader());
            head.setSenderKID(new DEROctetString("EMPTY".getBytes()));
            final ASN1Integer iteration = new ASN1Integer(iterationCount);

            // Create the new protected return message
            String objectId = "1.2.840.113533.7.66.13";
            if (badObjectId) {
                objectId += ".7";
            }
            final PBMParameter pp = new PBMParameter(derSalt, owfAlg, iteration, macAlg);
            final AlgorithmIdentifier pAlg = new AlgorithmIdentifier(new ASN1ObjectIdentifier(objectId), pp);
            head.setProtectionAlg(pAlg);

            // Calculate the protection bits
            final byte[] raSecret = password.getBytes();
            byte basekey[] = new byte[raSecret.length + salt.length];
            System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
            System.arraycopy(salt, 0, basekey, raSecret.length, salt.length);
            // Construct the base key according to rfc4210, section 5.1.3.1
            final MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), this.bcProvider);
            for (int i = 0; i < iterationCount; i++) {
                basekey = dig.digest(basekey);
                dig.reset();
            }
            // For HMAC/SHA1 there is another oid, that is not known in BC, but the result is the same so...
            final String macOid = macAlg.getAlgorithm().getId();
            final byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(head.build(), msg.getBody());
            final Mac mac = Mac.getInstance(macOid, this.bcProvider);
            final SecretKey key = new SecretKeySpec(basekey, macOid);
            mac.init(key);
            mac.reset();
            mac.update(protectedBytes, 0, protectedBytes.length);
            final byte[] out = mac.doFinal();
            final DERBitString bs = new DERBitString(out);

            return new PKIMessage(head.build(), msg.getBody(), bs, msg.getExtraCerts());
        }
        
        //TODO see if we could do this in a better way
        private PKIHeaderBuilder getHeaderBuilder(PKIHeader header) {
            PKIHeaderBuilder builder = new PKIHeaderBuilder(header.getPvno().getValue().intValue(), header.getSender(), header.getRecipient());
            builder.setFreeText(header.getFreeText());
            builder.setGeneralInfo(header.getGeneralInfo());
            builder.setMessageTime(header.getMessageTime());
            builder.setProtectionAlg(header.getProtectionAlg());
            builder.setRecipKID(header.getRecipKID().getOctets());
            builder.setRecipNonce(header.getRecipNonce());
            builder.setSenderKID(header.getSenderKID());
            builder.setSenderNonce(header.getSenderNonce());
            builder.setTransactionID(header.getTransactionID());
            return builder;
        }

        private byte[] sendCmpHttp(final byte[] message) throws Exception {
            final CMPSendHTTP send = CMPSendHTTP.doIt(message, StressTest.this.hostName, StressTest.this.port, StressTest.this.urlPath, false);
            if (send.responseCode != HttpURLConnection.HTTP_OK) {
                StressTest.this.performanceTest.getLog().error(
                        intres.getLocalizedMessage("cmp.responsecodenotok", Integer.valueOf(send.responseCode)));
                return null;
            }
            if (send.contentType == null) {
                StressTest.this.performanceTest.getLog().error("No content type received.");
                return null;
            }
            // Some appserver (Weblogic) responds with "application/pkixcmp; charset=UTF-8"
            if (!send.contentType.startsWith("application/pkixcmp")) {
                StressTest.this.performanceTest.getLog().info("wrong content type: " + send.contentType);
            }
            return send.response;
        }

        private boolean checkCmpResponseGeneral(final byte[] retMsg, final SessionData sessionData, final boolean requireProtection) throws Exception {
            // Parse response message
            final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
            if (respObject == null) {
                StressTest.this.performanceTest.getLog().error("No command response message.");
                return false;
            }

            // The signer, i.e. the CA, check it's the right CA
            final PKIHeader header = respObject.getHeader();
            if (header == null) {
                StressTest.this.performanceTest.getLog().error("No header in response message.");
                return false;
            }
            // Check that the signer is the expected CA
            final X500Name name = X500Name.getInstance(header.getSender().getName());
            if (header.getSender().getTagNo() != 4 || name == null || !name.equals(this.cacert.getSubjectDN())) {
                StressTest.this.performanceTest.getLog().error("Not signed by right issuer.");
            }

            if (header.getSenderNonce().getOctets().length != 16) {
                StressTest.this.performanceTest.getLog().error(
                        "Wrong length of received sender nonce (made up by server). Is " + header.getSenderNonce().getOctets().length
                                + " byte but should be 16.");
            }

            if (!Arrays.equals(header.getRecipNonce().getOctets(), sessionData.getNonce())) {
                StressTest.this.performanceTest.getLog().error(
                        "recipient nonce not the same as we sent away as the sender nonce. Sent: " + Arrays.toString(sessionData.getNonce())
                                + " Received: " + Arrays.toString(header.getRecipNonce().getOctets()));
            }

            if (!Arrays.equals(header.getTransactionID().getOctets(), sessionData.getTransId())) {
                StressTest.this.performanceTest.getLog().error("transid is not the same as the one we sent");
            }
            
            // Check that the message is signed with the correct digest alg
            final AlgorithmIdentifier algId = header.getProtectionAlg();
            if (algId == null || algId.getAlgorithm() == null || algId.getAlgorithm().getId() == null) {
                if (requireProtection) {
                    StressTest.this.performanceTest.getLog().error("Not possible to get algorithm.");
                    return false;
                }
                return true;
            }
            final String id = algId.getAlgorithm().getId();
            if (id.equals(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId())) {
                if (this.firstTime) {
                    this.firstTime = false;
                    this.isSign = true;
                    StressTest.this.performanceTest.getLog().info("Signature protection used.");
                } else if (!this.isSign) {
                    StressTest.this.performanceTest.getLog().error("Message password protected but should be signature protected.");
                }
            } else if (id.equals(CMPObjectIdentifiers.passwordBasedMac.getId())) {
                if (this.firstTime) {
                    this.firstTime = false;
                    this.isSign = false;
                    StressTest.this.performanceTest.getLog().info("Password (PBE) protection used.");
                } else if (this.isSign) {
                    StressTest.this.performanceTest.getLog().error("Message signature protected but should be password protected.");
                }
            } else {
                StressTest.this.performanceTest.getLog().error("No valid algorithm.");
                return false;
            }
            
            if (this.isSign) {
                // Verify the signature
                byte[] protBytes = CmpMessageHelper.getProtectedBytes(respObject);
                final DERBitString bs = respObject.getProtection();
                final Signature sig;
                try {
                    sig = Signature.getInstance(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId());
                    sig.initVerify(this.cacert);
                    sig.update(protBytes);
                    if (!sig.verify(bs.getBytes())) {
                        StressTest.this.performanceTest.getLog().error("CA signature not verifying");
                    }
                } catch (Exception e) {
                    StressTest.this.performanceTest.getLog().error("Not possible to verify signature.", e);
                }
            } else {
                // Verify the PasswordBased protection of the message
                final PBMParameter pp;

                final AlgorithmIdentifier pAlg = header.getProtectionAlg();
                pp = PBMParameter.getInstance(pAlg.getParameters());

                final int iterationCount = pp.getIterationCount().getPositiveValue().intValue();
                final AlgorithmIdentifier owfAlg = pp.getOwf();
                // Normal OWF alg is 1.3.14.3.2.26 - SHA1
                final AlgorithmIdentifier macAlg = pp.getMac();
                // Normal mac alg is 1.3.6.1.5.5.8.1.2 - HMAC/SHA1
                final byte[] salt = pp.getSalt().getOctets();
                final byte[] raSecret = new String("password").getBytes();
                // HMAC/SHA1 os normal 1.3.6.1.5.5.8.1.2 or 1.2.840.113549.2.7 
                final String macOid = macAlg.getAlgorithm().getId();
                final SecretKey key;

                byte[] basekey = new byte[raSecret.length + salt.length];
                System.arraycopy(raSecret, 0, basekey, 0, raSecret.length);
                System.arraycopy(salt, 0, basekey, raSecret.length, salt.length);
                // Construct the base key according to rfc4210, section 5.1.3.1
                final MessageDigest dig = MessageDigest.getInstance(owfAlg.getAlgorithm().getId(), this.bcProvider);
                for (int i = 0; i < iterationCount; i++) {
                    basekey = dig.digest(basekey);
                    dig.reset();
                }
                key = new SecretKeySpec(basekey, macOid);
                
                final Mac mac = Mac.getInstance(macOid, this.bcProvider);
                mac.init(key);
                mac.reset();
                final byte[] protectedBytes = CmpMessageHelper.getProtectedBytes(respObject);
                final DERBitString protection = respObject.getProtection();
                mac.update(protectedBytes, 0, protectedBytes.length);
                byte[] out = mac.doFinal();
                // My out should now be the same as the protection bits
                byte[] pb = protection.getBytes();
                if (!Arrays.equals(out, pb)) {
                    StressTest.this.performanceTest.getLog().error("Wrong PBE hash");
                }
            }
            return true;
        }

        private X509Certificate checkCmpCertRepMessage(final SessionData sessionData, final byte[] retMsg, final int requestId) throws IOException,
                CertificateException {
            // Parse response message
            final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
            if (respObject == null) {
                StressTest.this.performanceTest.getLog().error("No PKIMessage for certificate received.");
                return null;
            }
            final PKIBody body = respObject.getBody();
            if (body == null) {
                StressTest.this.performanceTest.getLog().error("No PKIBody for certificate received.");
                return null;
            }
            if (body.getType() != 8) {
                StressTest.this.performanceTest.getLog().error("Cert body tag not 8.");
                return null;
            }
            final CertRepMessage c = (CertRepMessage) body.getContent();
            if (c == null) {
                StressTest.this.performanceTest.getLog().error("No CertRepMessage for certificate received.");
                return null;
            }
            final CertResponse resp = c.getResponse()[0];
            if (resp == null) {
                StressTest.this.performanceTest.getLog().error("No CertResponse for certificate received.");
                return null;
            }
            if (resp.getCertReqId().getValue().intValue() != requestId) {
                StressTest.this.performanceTest.getLog().error(
                        "Received CertReqId is " + resp.getCertReqId().getValue().intValue() + " but should be " + requestId);
                return null;
            }
            final PKIStatusInfo info = resp.getStatus();
            if (info == null) {
                StressTest.this.performanceTest.getLog().error("No PKIStatusInfo for certificate received.");
                return null;
            }
            if (info.getStatus().intValue() != 0) {
                StressTest.this.performanceTest.getLog().error("Received Status is " + info.getStatus().intValue() + " but should be 0");
                return null;
            }
            final CertifiedKeyPair kp = resp.getCertifiedKeyPair();
            if (kp == null) {
                StressTest.this.performanceTest.getLog().error("No CertifiedKeyPair for certificate received.");
                return null;
            }
            final CertOrEncCert cc = kp.getCertOrEncCert();
            if (cc == null) {
                StressTest.this.performanceTest.getLog().error("No CertOrEncCert for certificate received.");
                return null;
            }
            final CMPCertificate cmpcert = cc.getCertificate();
            if (cmpcert == null) {
                StressTest.this.performanceTest.getLog().error("No X509CertificateStructure for certificate received.");
                return null;
            }
            final byte encoded[] = cmpcert.getEncoded();
            if (encoded == null || encoded.length <= 0) {
                StressTest.this.performanceTest.getLog().error("No encoded certificate received.");
                return null;
            }
            final X509Certificate cert = (X509Certificate) this.certificateFactory.generateCertificate(new ByteArrayInputStream(encoded));
            if (cert == null) {
                StressTest.this.performanceTest.getLog().error("Not possbile to create certificate.");
                return null;
            }
            // Remove this test to be able to test unid-fnr
            if (cert.getSubjectDN().hashCode() != new X500Name(CertTools.getSubjectDN(extraCert)).hashCode()) {
                StressTest.this.performanceTest.getLog().error(
                        "Subject is '" + cert.getSubjectDN() + "' but should be '" + CertTools.getSubjectDN(extraCert) + '\'');
                return null;
            }
            if (cert.getIssuerX500Principal().hashCode() != this.cacert.getSubjectX500Principal().hashCode()) {
                StressTest.this.performanceTest.getLog().error(
                        "Issuer is '" + cert.getIssuerDN() + "' but should be '" + this.cacert.getSubjectDN() + '\'');
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

        private boolean checkCmpPKIConfirmMessage(final SessionData sessionData, final byte retMsg[]) throws IOException {
            // Parse response message
            final PKIMessage respObject = PKIMessage.getInstance(new ASN1InputStream(new ByteArrayInputStream(retMsg)).readObject());
            if (respObject == null) {
                StressTest.this.performanceTest.getLog().error("Not possbile to get response message.");
                return false;
            }
            final PKIHeader header = respObject.getHeader();
            if (header.getSender().getTagNo() != 4) {
                StressTest.this.performanceTest.getLog().error(
                        "Wrong tag in response message header. Is " + header.getSender().getTagNo() + " should be 4.");
                return false;
            }
            {
                final X500Name name = X500Name.getInstance(header.getSender().getName());
                String senderDN = name.toString().replaceAll(" ", "");
                String caDN = this.cacert.getSubjectDN().toString().replaceAll(" ", "");
                if (!StringUtils.equals(senderDN, caDN)) {
                    StressTest.this.performanceTest.getLog().error("Wrong CA DN. Is '" + name + "' should be '" + this.cacert.getSubjectDN() + "'.");
                    return false;
                }
            }
            {
                final X500Name name = X500Name.getInstance(header.getRecipient().getName());
                if (name.hashCode() != new X500Name(CertTools.getSubjectDN(extraCert)).hashCode()) {
                    StressTest.this.performanceTest.getLog().error(
                            "Wrong recipient DN. Is '" + name + "' should be '" + CertTools.getSubjectDN(extraCert) + "'.");
                    return false;
                }
            }
            final PKIBody body = respObject.getBody();
            if (body == null) {
                StressTest.this.performanceTest.getLog().error("No PKIBody for response received.");
                return false;
            }
            if (body.getType() != 19) {
                StressTest.this.performanceTest.getLog().error("Cert body tag not 19. It was " + body.getType());

                PKIStatusInfo err = (PKIStatusInfo) body.getContent();
                StressTest.this.performanceTest.getLog().error(err.getStatusString().getStringAt(0).getString());

                return false;
            }
            final DERNull n = (DERNull) body.getContent();
            if (n == null) {
                StressTest.this.performanceTest.getLog().error("Confirmation is null.");
                return false;
            }
            return true;
        }

        private PKIMessage genCertConfirm(final SessionData sessionData, final String hash) {
            PKIHeaderBuilder myPKIHeader = new PKIHeaderBuilder(2, new GeneralName(new X500Name(CertTools.getSubjectDN(this.extraCert))),
                    new GeneralName(new X500Name(this.cacert.getSubjectDN().getName())));
            myPKIHeader.setMessageTime(new DERGeneralizedTime(new Date()));
            // senderNonce
            myPKIHeader.setSenderNonce(new DEROctetString(sessionData.getNonce()));
            // TransactionId
            myPKIHeader.setTransactionID(new DEROctetString(sessionData.getTransId()));

            CertStatus cs = new CertStatus(hash.getBytes(), new BigInteger(Integer.toString(sessionData.getReqId())));
            CertConfirmContent cc = CertConfirmContent.getInstance(cs);
            PKIBody myPKIBody = new PKIBody(24, cc); // Cert Confirm
            PKIMessage myPKIMessage = new PKIMessage(myPKIHeader.build(), myPKIBody);
            return myPKIMessage;
        }

        private class GetCertificate implements Command {
            private final SessionData sessionData;

            private GetCertificate(final SessionData sd) {
                this.sessionData = sd;
            }

            public boolean doIt() throws Exception {
                this.sessionData.newSession();

                CertRequest keyUpdateReq = genKeyUpdateReq();
                AlgorithmIdentifier pAlg = new AlgorithmIdentifier(PKCSObjectIdentifiers.sha1WithRSAEncryption);
                PKIMessage certMsg = genPKIMessage(this.sessionData, true, keyUpdateReq, pAlg, null);
                if (certMsg == null) {
                    StressTest.this.performanceTest.getLog().error("No certificate request.");
                    return false;
                }

                PKIMessage signedMsg = signPKIMessage(certMsg, oldKey);
                addExtraCert(signedMsg, extraCert);
                if (signedMsg == null) {
                    StressTest.this.performanceTest.getLog().error("No protected message.");
                    return false;
                }

                CertReqMessages kur = (CertReqMessages) signedMsg.getBody().getContent();
                this.sessionData.setReqId(kur.toCertReqMsgArray()[0].getCertReq().getCertReqId().getValue().intValue());
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(signedMsg);
                final byte[] ba = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba);
                if (resp == null || resp.length <= 0) {
                    StressTest.this.performanceTest.getLog().error("No response message.");
                    return false;
                }
                if (!checkCmpResponseGeneral(resp, this.sessionData, true)) {
                    return false;
                }
                final X509Certificate cert = checkCmpCertRepMessage(this.sessionData, resp, this.sessionData.getReqId());
                if (cert == null) {
                    return false;
                }
                String fp = CertTools.getFingerprintAsString((Certificate) cert);
                this.sessionData.setFP(fp);
                final BigInteger serialNumber = CertTools.getSerialNumber(cert);
                if (StressTest.this.resultCertFilePrefix != null) {
                    new FileOutputStream(StressTest.this.resultCertFilePrefix + serialNumber + ".dat").write(cert.getEncoded());
                }
                StressTest.this.performanceTest.getLog().result(serialNumber);

                return true;
            }

            public String getJobTimeDescription() {
                return "Get certificate";
            }

        }

        private class SendConfirmMessageToCA implements Command {
            private final SessionData sessionData;

            private SendConfirmMessageToCA(final SessionData sd) {
                this.sessionData = sd;
            }

            public boolean doIt() throws Exception {
                final String hash = this.sessionData.getFP(); //"foo123";
                final PKIMessage con = genCertConfirm(this.sessionData, hash);
                if (con == null) {
                    StressTest.this.performanceTest.getLog().error("Not possible to generate PKIMessage.");
                    return false;
                }
                final PKIMessage confirm = protectPKIMessage(con, false, eepassword);
                final ByteArrayOutputStream bao = new ByteArrayOutputStream();
                final DEROutputStream out = new DEROutputStream(bao);
                out.writeObject(confirm);
                final byte ba[] = bao.toByteArray();
                // Send request and receive response
                final byte[] resp = sendCmpHttp(ba);
                if (resp == null || resp.length <= 0) {
                    StressTest.this.performanceTest.getLog().error("No response message.");
                    return false;
                }
                if (!checkCmpResponseGeneral(resp, this.sessionData, false)) {
                    return false;
                }
                if (!checkCmpPKIConfirmMessage(this.sessionData, resp)) {
                    return false;
                }
                return true;
            }

            public String getJobTimeDescription() {
                return "Send confirmation to CA";
            }
        }

        private class SessionData {
            private final byte[] nonce = new byte[16];
            private final byte[] transid = new byte[16];
            private int reqId;
            private String newcertfp;

            SessionData() {
                super();
            }

            void newSession() {
                StressTest.this.performanceTest.getRandom().nextBytes(this.nonce);
                StressTest.this.performanceTest.getRandom().nextBytes(this.transid);
            }

            int getReqId() {
                return this.reqId;
            }

            void setReqId(int i) {
                this.reqId = i;
            }

            void setFP(String fp) {
                this.newcertfp = fp;
            }

            String getFP() {
                return this.newcertfp;
            }

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
                return new Command[] { new GetCertificate(sessionData), new SendConfirmMessageToCA(sessionData) };//, new Revoke(sessionData)};
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
        final int port;
        //        final boolean isHttp;
        final String urlPath;
        final String resultFilePrefix;
        if (args.length < 5) {
            System.out
                    .println(args[0]
                            + " <host name> <keystore (p12)> <keystore password> <friendlyname in keystore> [<number of threads>] [<wait time (ms) between each thread is started>] [<port>] [<URL path of servlet. use 'null' to get EJBCA (not proxy) default>] [<certificate file prefix. set this if you want all received certificates stored on files>]");
            System.out
                    .println("EJBCA build configuration requirements: cmp.operationmode=normal, cmp.allowraverifypopo=true, cmp.allowautomatickeyupdate=true, cmp.allowupdatewithsamekey=true");
            System.out
                    .println("Ejbca expects the following: There exists an end entity with a generated certificate. The end entity's certificate and its private key are stored in the keystore used "
                            + "in the commandline. The end entity's certificate's 'friendly name' in the keystore is the one used in the command line. Such keystore can be obtained, for example, by specifying "
                            + "the token to be 'P12' when creating the end entity and then download the keystore by choosing 'create keystore' from the public web");
            return;
        }
        hostName = args[1];
        keystoreFile = args[2];
        keystorePassword = args[3];
        certNameInKeystore = args[4];
        numberOfThreads = args.length > 5 ? Integer.parseInt(args[5].trim()) : 1;
        waitTime = args.length > 6 ? Integer.parseInt(args[6].trim()) : 0;
        port = args.length > 7 ? Integer.parseInt(args[7].trim()) : 8080;
        urlPath = args.length > 8 && args[8].toLowerCase().indexOf("null") < 0 ? args[8].trim() : null;
        resultFilePrefix = args.length > 9 ? args[9].trim() : null;

        CryptoProviderTools.installBCProviderIfNotAvailable();

        Certificate cacert = null;
        Certificate extracert = null;
        PrivateKey oldCertKey = null;

        FileInputStream file_inputstream;
        try {
            file_inputstream = new FileInputStream(keystoreFile);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(file_inputstream, keystorePassword.toCharArray());
            Key key = keyStore.getKey(certNameInKeystore, keystorePassword.toCharArray());
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(key.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            oldCertKey = keyFactory.generatePrivate(keySpec);

            Certificate[] certs = keyStore.getCertificateChain(certNameInKeystore);
            extracert = certs[0];
            cacert = certs[1];

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
            new StressTest(hostName, port, numberOfThreads, waitTime, urlPath, resultFilePrefix, keystorePassword, (X509Certificate) cacert, oldCertKey, extracert);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    protected String getName() {
        return "CMPKeyUpdateStressTest";
    }

}
