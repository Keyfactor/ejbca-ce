package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.log4j.Logger;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.smime.SMIMECapability;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.cms.*;

/**
 * Class to handle SCEP request messages sent to the CA.
 *
 * @version  $Id: ScepRequestMessage.java,v 1.8 2003-02-12 11:23:18 scop Exp $
 */
public class ScepRequestMessage implements IRequestMessage, Serializable {

    private static Logger log = Logger.getLogger(ScepRequestMessage.class);

    private static String id_Verisign = "2.16.840.1.113733";
    private static String id_pki = id_Verisign + ".1";
    private static String id_attributes = id_pki + ".9";
    private static String id_messageType = id_attributes + ".2";
    private static String id_pkiStatus = id_attributes + ".3";
    private static String id_failInfo = id_attributes + ".4";
    private static String id_senderNonce = id_attributes + ".5";
    private static String id_recipientNonce = id_attributes + ".6";
    private static String id_transId = id_attributes + ".7";
    private static String id_extensionReq = id_attributes + ".8";

    /** Raw form of the PKCS10 message
     */
    private byte[] msg;

    /** Signed data, the whole enchilada to to speak...
     */
    private transient SignedData sd = null;
    /** Enveloped data, carrying the 'beef' of the request
     */
    private transient EnvelopedData envData = null;
    /** Enveloped data, carrying the 'beef' of the request
     */
    private transient ContentInfo envEncData = null;

    /** Certificate used for decryption, verification
     */
    private X509Certificate cert=null;
    /** Private key used for decryption.
     */
    private PrivateKey privateKey=null;
    /** The contained pkcs10 request message
     */
    private transient PKCS10CertificationRequest pkcs10 = null;

    /** The messageType attribute specify the type of operation performed by the
     * transaction. This attribute is required in all PKI messages. Currently, the following message types are defined:
     * PKCSReq (19)  -- Permits use of PKCS#10 certificate request
     * CertRep (3)   -- Response to certificate or CRL request
     * GetCertInitial (20)  -- Certificate polling in manual enrollment
     * GetCert (21)  -- Retrieve a certificate
     * GetCRL  (22)  -- Retrieve a CRL
     */
    private int messageType = 0;
    /** SenderNonce in a request is used as recipientNonce when the server sends back a reply to the client
    */
    private String sendeNonce = null;
    /** Type of error
     */
    int error = 0;

    /** Constucts a new SCEP/PKCS7 message handler object.
     * @param msg The DER encoded PKCS7 request.
     * @throws IOException if the request can not be parsed.
     */
    public ScepRequestMessage(byte[] msg) throws IOException {
        log.debug(">ScepRequestMessage");
        this.msg = msg;
        init();
        log.debug("<ScepRequestMessage");
    }

    private void init() throws IOException {
        log.debug(">init");
        //Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        //int result = Security.addProvider(BCJce);
        // Parse and verify the entegrity of the PKIOperation message PKCS#7

        /* If this would have been done using the newer CMS it would have made me so much happier... */
        ASN1Sequence seq =(ASN1Sequence)new DERInputStream(new ByteArrayInputStream(msg)).readObject();
        ContentInfo ci = new ContentInfo(seq);
        String ctoid = ci.getContentType().getId();
        if (ctoid.equals(CMSObjectIdentifiers.signedData.getId())) {
            // This is SignedData so it is a pkcsCertReqSigned,
            //  pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
            // (could also be pkcsRepSigned or certOnly, but we don't receive them on the server side

            // Try to find out what kind of message this is
            sd = new SignedData((ASN1Sequence)ci.getContent());
            Enumeration sis = sd.getSignerInfos().getObjects();
            if (sis.hasMoreElements()) {
                SignerInfo si = new SignerInfo((ASN1Sequence)sis.nextElement());
                Enumeration attr = si.getAuthenticatedAttributes().getObjects();
                //Vector attr = si.getSignedAttrs().getAttributes();
                while (attr.hasMoreElements()) {
                    Attribute a = new Attribute((ASN1Sequence)attr.nextElement());
                    //Attribute a = (Attribute)iter.next();
                    log.debug("Found attribute: "+a.getAttrType().getId());
                    if (a.getAttrType().getId().equals(id_messageType)) {
                        Enumeration values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        messageType = Integer.parseInt(str.getString());
                        log.debug("Messagetype = "+messageType);
                        break; // we can olny handle one message type per message :-)
                    }
                }
            }
            // If this is a PKCSReq
            if (messageType == 19) {
                // Extract the contents, which is an encrypted PKCS10
                ci = sd.getEncapContentInfo();
                ctoid = ci.getContentType().getId();
                if (ctoid.equals(CMSObjectIdentifiers.data.getId())) {
                    DEROctetString content = (DEROctetString)ci.getContent();
                    log.debug("envelopedData is "+content.getOctets().length+" bytes.");
                    ASN1Sequence seq1 =(ASN1Sequence)new DERInputStream(new ByteArrayInputStream(content.getOctets())).readObject();
                    envEncData = new ContentInfo(seq1);
                    ctoid = envEncData.getContentType().getId();
                    if (ctoid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
                        envData = new EnvelopedData((ASN1Sequence)envEncData.getContent());
                    } else {
                        log.error("EncapsulatedContentInfo does not contain PKCS7 envelopedData: "+ctoid);
                        error = 2;
                    }
                } else {
                    log.error("EncapsulatedContentInfo is not of type 'data': "+ctoid);
                    error = 3;
                }

            } else {
                log.error("This is not a certification request!");
                error = 4;
            }
        } else {
            log.error("PKCSReq does not contain 'signedData': "+ctoid);
            error = 1;
        }
        log.debug("<init");
    } // init

    private void decrypt() throws NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, CMSException,
    NoSuchProviderException, BadPaddingException, InvalidAlgorithmParameterException, GeneralSecurityException, IOException {
        log.debug(">decrypt");
        // Now we are getting somewhere (pheew),
        // Now we just have to get the damn key...to decrypt the PKCS10
        if (envEncData == null) {
            log.error("No enveloped data to decrypt!");
            return;
        }
            CMSEnvelopedData ed = new CMSEnvelopedData(envEncData);

            RecipientInformationStore  recipients = ed.getRecipientInfos();

            Collection  c = recipients.getRecipients();
            Iterator    it = c.iterator();

            byte[] pkcs10Bytes = null;
            while (it.hasNext())
            {
                RecipientInformation   recipient = (RecipientInformation)it.next();

                pkcs10Bytes = recipient.getContent(privateKey, "BC");
                break;
            }
/*
        if (envData == null) {
            log.error("No enveloped data to decrypt!");
            return;
        }
        Enumeration ris = envData.getRecipientInfos().getObjects();
        if (ris.hasMoreElements()) {
            RecipientInfo ri = RecipientInfo.getInstance(ris.nextElement());
            DEREncodable info = ri.getInfo();
            if (info instanceof KeyTransRecipientInfo) {
                KeyTransRecipientInfo kti = (KeyTransRecipientInfo)info;
                AlgorithmIdentifier keyEncAlg = AlgorithmIdentifier.getInstance(kti.getKeyEncryptionAlgorithm());
                String id = keyEncAlg.getObjectId().getId();
                if(id.equals(PKCSObjectIdentifiers.rsaEncryption.getId())) {
                    log.debug("Found key encrypted with RSA inside message.");
                    //RecipientIdentifier rid = kti.getRecipientIdentifier();
                    DEREncodable rid = kti.getRecipientIdentifier().getId();
                    if (rid instanceof IssuerAndSerialNumber) {
                        log.debug("Issuer and serialnumer of recipient:");
                        log.debug("Issuer: "+((IssuerAndSerialNumber)rid).getName().toString());
                        log.debug("SerialNo: "+((IssuerAndSerialNumber)rid).getSerialNumber().getValue().toString());
                        log.debug("My key Issuer: "+cert.getIssuerDN().toString());
                        log.debug("My serialNo: "+cert.getSerialNumber().toString());
                    }

                    //boolean ok = checkKeys(cert.getPublicKey(), privateKey);
                    //if (!ok) {
                    //    log.error("Public and private keys do not match!");
                    //    return;
                    //}

                    // At least OpenSCEP uses nopadding, go figure...
//                    Cipher cipher = Cipher.getInstance("RSA/NONE/NOPADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/ECB/NOPADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPPADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/ECB/ISO9796-1PADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/NONE/NOPADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/NONE/ISO9796-1PADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/1/PCKS1PADDING", "BC");
//                    Cipher cipher = Cipher.getInstance("RSA/2/PCKS1PADDING", "BC");
                    Cipher cipher = Cipher.getInstance(id, "BC");
                    cipher.init(Cipher.DECRYPT_MODE, privateKey);
                    log.info("blocksize="+cipher.getBlockSize());
                    log.info("keysize="+((RSAPrivateKey)privateKey).getPrivateExponent().bitLength());
                    byte[] encKey = kti.getEncryptedKey().getOctets();
                    log.info("Encrypted keybytes: "+encKey.length);
                    byte[] dekBytes = cipher.doFinal(encKey);
                    log.info("Decrypted keybytes: "+dekBytes.length);
                    byte[] cekBytes = unpad(dekBytes);
                    log.info("Unpadded keybytes: "+cekBytes.length);
                    AlgorithmIdentifier aid = envData.getEncryptedContentInfo().getContentEncryptionAlgorithm();
                    String alg = aid.getObjectId().getId();
                    log.info("Symm alg="+alg);
                    AlgorithmParameterSpec iv = getIv(alg, aid.getParameters());
                    SecretKey cek = getContentEncryptionKey(cekBytes, alg);
                    log.debug("Extracted secret key.");
                    byte[] enc = envData.getEncryptedContentInfo().getEncryptedContent().getOctets();
                    FileOutputStream fos1 = new FileOutputStream("C:\\pkcs10.enc");
                    fos1.write(enc);
                    fos1.close();

                    cipher = getCipher(alg);
                    if(iv == null) {
                        log.debug("IV is null.");
                        cipher.init(Cipher.DECRYPT_MODE, cek);
                    } else {
                        log.debug("IV is NOT null.");
                    log.info("blocksize="+cipher.getBlockSize());
                    log.info("key alg="+cek.getAlgorithm());
                    log.info("enc key size="+cekBytes.length);
                    cipher.init(Cipher.DECRYPT_MODE, cek, iv);
                    }
                    byte[] pkcs10Bytes = unpad(cipher.doFinal(enc));

                    FileOutputStream fos = new FileOutputStream("C:\\pkcs10.txt");
                    fos.write(Base64.encode(pkcs10Bytes));
                    fos.close();
                    DERObject derobj = new DERInputStream(new ByteArrayInputStream(pkcs10Bytes)).readObject();
                    DERConstructedSequence seq = (DERConstructedSequence)derobj;
                    pkcs10 = new PKCS10CertificationRequest(seq);
                    log.debug("Successfully extracted PKCS10.");
                } else {
                    log.error("Key not encrypted with RSA!");
                    error = 4;
                }
            } else {
                log.error("RecipientInfo is not KeyTransRecipientInfo!");
                error = 5;
            }
        }
        */
        log.debug("<decrypt");
    } // decrypt

    public PublicKey getRequestPublicKey() {
        log.debug(">getRequestPublicKey()");
        PublicKey ret = null;
        try {
            if (envData == null) {
                init();
                decrypt();
            }
            ret = pkcs10.getPublicKey();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
            return null;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
            return null;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
            return null;
        }
        log.debug("<getRequestPublicKey()");
        return ret;
    }

    public boolean verify() {
        log.debug(">verify()");
        boolean ret = false;
        try {
            if (pkcs10 == null) {
                init();
                decrypt();
            }
            ret = pkcs10.verify();
        } catch (IOException e) {
            log.error("PKCS7 not inited!");
            return false;
        } catch (GeneralSecurityException e) {
            log.error("Error in PKCS7:", e);
            return false;
        } catch (CMSException e) {
            log.error("Error in PKCS7:", e);
            return false;
        }
        log.debug("<verify()");
        return ret;
    }

    public boolean requireKeyInfo() {
        return true;
    }
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
        this.cert = cert;
        this.privateKey = key;
    }

    //
    // Private helper methods
    //
    private static boolean checkKeys(PublicKey pubK, PrivateKey privK) {
        String in = "foo123";
        byte[] text = in.getBytes();
        try {
            Cipher cipher1 = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
            cipher1.init(Cipher.ENCRYPT_MODE, pubK);
            byte[] textout = cipher1.doFinal(text);
            Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
            cipher2.init(Cipher.DECRYPT_MODE, privK);
            byte[] out = cipher2.doFinal(textout);
            log.debug("out="+new String(out));
            return in.equals(new String(out));
        } catch (Exception e) {
            return false;
        }
    }

    private static Cipher getCipher(String _alg)
        throws CMSException, GeneralSecurityException {

        if(_alg.equals(SMIMECapability.dES_CBC.getId())) {
            return Cipher.getInstance("DES", "BC");
        } else if(_alg.equals(PKCSObjectIdentifiers.des_EDE3_CBC.getId())) {
            return Cipher.getInstance("DESEDE/CBC/NoPadding", "BC");
        }
        else if(_alg.equals(PKCSObjectIdentifiers.RC2_CBC.getId())) {
            return Cipher.getInstance("RC2/CBC/NoPadding", "BC");
        }
        else {
            throw new CMSException("Invalid cipher algorithm");
        }
    }

    private static SecretKey getContentEncryptionKey(byte[] _keyBytes, String _alg)
        throws CMSException {

        if(_alg.equals(SMIMECapability.dES_CBC.getId())) {
            return new SecretKeySpec(_keyBytes, "DES");
        } else if(_alg.equals(PKCSObjectIdentifiers.des_EDE3_CBC.getId())) {
            return new SecretKeySpec(_keyBytes, "DESEDE");
        }
        else if(_alg.equals(PKCSObjectIdentifiers.RC2_CBC.getId())) {
            return new SecretKeySpec(_keyBytes, "RC2");
        }
        else {
            throw new CMSException("Invalid content encryption key algorithm");
        }
    }

    // RFC 2630 6.3
    private static byte[] unpad(byte[] _dec) {
        byte _pad    = _dec[_dec.length - 1];
        int  _padInt = 0x000000FF & _pad;

        if((_padInt < 1) || (_padInt > 8)) {
            log.info("Unpadded");
            return _dec;
        }

        boolean _padded = true;
        for(int i = 1; i <= _padInt; i++) {
            byte _p = _dec[_dec.length - i];
            if(_p != _pad) {
                _padded = false;
                break;
            }
        }

        if(_padded) {
            log.info("Padded");

            byte[] _buf = new byte[_dec.length - _padInt];
            System.arraycopy(_dec, 0, _buf, 0, _buf.length);
            return _buf;
        }
        log.info("Unpadded");

        return _dec;
    }

    private static AlgorithmParameterSpec getIv(String alg, DEREncodable tmp)
        throws CMSException
    {
        // get 3des parameter spec
        log.debug("alg="+alg);
        if(alg.equals(SMIMECapability.dES_CBC.getId())) {
            ASN1OctetString iv = (ASN1OctetString)tmp;
            byte[] ivoct = iv.getOctets();
            log.info("IV length ="+ivoct.length);

            return new IvParameterSpec( ivoct );
        } else if(alg.equals(PKCSObjectIdentifiers.des_EDE3_CBC.getId())) {
            ASN1OctetString iv = (ASN1OctetString)tmp;
            return new IvParameterSpec( iv.getOctets() );
        }
        // get rc2 parameter spec
        else if(alg.equals(PKCSObjectIdentifiers.RC2_CBC.getId())) {
            // retrieve key parameter version and spec bytes
            //TODO:
        }
        else
        {
            throw new CMSException("Invalid cipher algorithm");
        }
        return null;
    }
} // ScepRequestMessage
