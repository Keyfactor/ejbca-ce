package se.anatom.ejbca.protocol;

import java.io.*;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.GeneralSecurityException;
import java.util.Enumeration;
import java.util.Iterator;

import org.apache.log4j.*;

import org.bouncycastle.jce.PKCS7SignedData;
import org.bouncycastle.asn1.*;
import org.bouncycastle.cms.asn1.*;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.parsers.SignedDataParser;
import org.bouncycastle.cms.parsers.EnvelopedDataParser;

/** Class to handle PKCS7 request messages sent to the CA.
 *
* @version  $Id: PKCS7RequestMessage.java,v 1.2 2002-10-14 15:29:49 anatom Exp $
 */
public class PKCS7RequestMessage implements RequestMessage, Serializable {

    static private Category cat = Category.getInstance( PKCS7RequestMessage.class.getName() );

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

    /** Certificate used for decryption, verification
     */
    private X509Certificate cert;
    /** Private key used for decryption.
     */
    private PrivateKey privateKey;

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

    /** Constucts a new PKCS7 message handler object.
     * @param msg The DER encoded PKCS7 request.
     * @throws IOException if the request can not be parsed.
     */
    public PKCS7RequestMessage(byte[] msg) throws IOException {
        cat.debug(">PKCS7RequestMessage");
        this.msg = msg;
        init();
        cat.debug("<PKCS7RequestMessage");
    }

    private void init() throws IOException {
        // Parse and verify the entegrity of the PKIOperation message PKCS#7

        // TODO: Use SignedDataParser to verify the message

        /* If this would have been done using the newer CMS it would have made me so much happier... */
        DERConstructedSequence seq =(DERConstructedSequence)(new DERInputStream(new ByteArrayInputStream(msg)).readObject());
        ContentInfo ci = new ContentInfo(seq);
        String ctoid = ci.getContentType().getId();
        if (ctoid.equals(CMSObjectIdentifiers.signedData.getId())) {
            // This is SignedData so it is a pkcsCertReqSigned,
            //  pkcsGetCertInitialSigned, pkcsGetCertSigned, pkcsGetCRLSigned
            // (could also be pkcsRepSigned or certOnly, but we don't receive them on the server side

            // Try to find out what kind of message this is
            sd = new SignedData((DERConstructedSequence)ci.getContent());
            Enumeration sis = sd.getSignerInfos().getObjects();
            if (sis.hasMoreElements()) {
                SignerInfo si = new SignerInfo((ASN1Sequence)sis.nextElement());
                Enumeration attr = si.getAuthenticatedAttributes().getObjects();
                //Vector attr = si.getSignedAttrs().getAttributes();
                while (attr.hasMoreElements()) {
                    Attribute a = new Attribute((ASN1Sequence)attr.nextElement());
                    //Attribute a = (Attribute)iter.next();
                    cat.debug("Found attribute: "+a.getAttrType());
                    if (a.getAttrType().equals(id_messageType)) {
                        Enumeration values = a.getAttrValues().getObjects();
                        DERPrintableString str = DERPrintableString.getInstance(values.nextElement());
                        messageType = Integer.parseInt(str.getString());
                        cat.debug("Messagetype = "+messageType);
                    }
                }
            }
            // If this is a PKCSReq
            if (messageType == 19) {
                // Extract the contents, which is an encrypted PKCS10
                ci = sd.getEncapContentInfo();
                ctoid = ci.getContentType().getId();
                if (ctoid.equals(CMSObjectIdentifiers.data.getId())) {
                    DEREncodable content = ci.getContent();
                    ByteArrayOutputStream bOut = new ByteArrayOutputStream();
                    DEROutputStream dOut = new DEROutputStream(bOut);
                    dOut.writeObject(content);
                    dOut.close();
                    cat.debug("envelopedData is: "+new String(bOut.toByteArray()));
                    //DERConstructedSequence seq1 =(DERConstructedSequence)(new DERInputStream(new ByteArrayInputStream(bOut.toByteArray())).readObject());
                    ci = new ContentInfo((DERConstructedSequence)content);
                    ctoid = ci.getContentType().getId();
                    if (ctoid.equals(CMSObjectIdentifiers.envelopedData.getId())) {
                        envData = new EnvelopedData((DERConstructedSequence)ci.getContent());
                    } else {
                        cat.error("EncapsulatedContentInfo does not contain PKCS7 envelopedData: "+ctoid);
                        error = 2;
                    }
                    //EnvelopedDataParser parser = EnvelopedDataParser.getData(envData, cert, privatekey);

                    /* Replaced by the above EnvelopedDataParser
                    EncryptedContent encData = envData.getEncryptedContentInfo().getEncryptedContent();
                    // Now we are getting somewhere (pheew), have the enrypted PKCS10
                    // Now we just have to get the damn key...
                    Vector ris = envData.getRecipientInfos().getInfos();
                    if (ris.size() > 0) {
                        RecipientInfo ri =(RecipientInfo)ris.get(0);
                        KeyTransRecipientInfo kti = KeyTransRecipientInfo.getInstance(ri.getInfo());
                        EncryptedKey encKey = kti.getEncryptedKey()
                    }
                    */
                } else {
                    cat.error("EncapsulatedContentInfo is not of type 'data': "+ctoid);
                    error = 3;
                }

            }

        } else {
            cat.error("PKCSReq does not contain 'signedData': "+ctoid);
            error = 1;
        }
    }

    public PublicKey getRequestPublicKey() {
        cat.debug(">getRequestPublicKey()");
        try {
            if (envData == null)
                init();
        } catch (IOException e) {
            cat.error("PKCS7 not inited!");
            return null;
        }
        // TODO:
        //return pkcs10.getPublicKey();
        cat.debug("<getRequestPublicKey()");
        return null;
    }

    public boolean verify() {
        cat.debug(">verify()");
        boolean ret = false;
        /*
        try {
            if (sd == null)
                init();
            ret = SignedDataParser.verify(sd, cert);
        } catch (IOException e) {
            cat.error("PKCS7 not inited!");
        } catch (GeneralSecurityException e) {
            cat.error("Error in PKCS7:", e);
            throw e;
        } catch (CMSException e) {
            cat.error("Error in PKCS7:", e);
        }
        */
        cat.debug("<verify()");
        return ret;
    }

    public boolean requireKeyInfo() {
        return true;
    }
    public void setKeyInfo(X509Certificate cert, PrivateKey key) {
        this.cert = cert;
        this.privateKey = key;
    }

} // PKCS7RequestMessage
