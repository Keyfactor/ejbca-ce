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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.log4j.Logger;

import org.bouncycastle.jce.PKCS10CertificationRequest;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.*;
import org.bouncycastle.cms.*;

/**
 * Class to handle SCEP request messages sent to the CA.
 *
 * @version  $Id: ScepRequestMessage.java,v 1.15 2003-06-11 12:20:01 anatom Exp $
 */
public class ScepRequestMessage extends PKCS10RequestMessage implements IRequestMessage, Serializable {

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

    /** Raw form of the Scep message
     */
    private transient byte[] scepmsg;

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
    public ScepRequestMessage(byte[] msg) throws IOException, InvalidKeyException, GeneralSecurityException, CMSException {
        log.debug(">ScepRequestMessage");
        this.scepmsg = msg;
        init();
        log.debug("<ScepRequestMessage");
    }

    private void init() throws IOException {
        log.debug(">init");
        //Provider BCJce = new org.bouncycastle.jce.provider.BouncyCastleProvider();
        //int result = Security.addProvider(BCJce);
        // Parse and verify the entegrity of the PKIOperation message PKCS#7

        /* If this would have been done using the newer CMS it would have made me so much happier... */
        ASN1Sequence seq =(ASN1Sequence)new DERInputStream(new ByteArrayInputStream(scepmsg)).readObject();
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
        if (privateKey == null) {
            log.error("Need private key to decrypt!");
            return;
        }
        if (envEncData == null) {
            log.error("No enveloped data to decrypt!");
            return;
        }
        
        CMSEnvelopedData ed = new CMSEnvelopedData(envEncData);
        RecipientInformationStore  recipients = ed.getRecipientInfos();
        Collection  c = recipients.getRecipients();
        Iterator it = c.iterator();
        byte[] pkcs10Bytes = null;
        while (it.hasNext())
        {
            RecipientInformation   recipient = (RecipientInformation)it.next();
            pkcs10Bytes = recipient.getContent(privateKey, "BC");
            break;
        }            
        DERObject derobj = new DERInputStream(new ByteArrayInputStream(pkcs10Bytes)).readObject();
        ASN1Sequence seq = (ASN1Sequence)derobj;
        pkcs10 = new PKCS10CertificationRequest(seq);
        log.debug("Successfully extracted PKCS10.");
        log.debug("<decrypt");
    } // decrypt

    /** Returns the public key from the certificattion request.
    * @return public key from certification request.
    */
    public PublicKey getRequestPublicKey() {
        log.debug(">getRequestPublicKey()");
        PublicKey ret = null;
        try {
            if (envData == null) {
                init();
                decrypt();
            }
            ret = super.getRequestPublicKey();
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
            ret = super.verify();
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
        String in = "TheTopSecretTestString";
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

} // ScepRequestMessage
