package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.util.ArrayList;

import org.apache.log4j.Logger;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;

/** A response message for scep (pkcs7).
*
* @version  $Id: ScepResponseMessage.java,v 1.1 2003-06-13 19:54:19 anatom Exp $
*/
public class  ScepResponseMessage implements IResponseMessage {

    private static Logger log = Logger.getLogger(ScepResponseMessage.class);

    private transient Certificate cert = null;
    private transient int status = 0;

    private X509Certificate signCert = null;
    private PrivateKey signKey = null;
    private X509Certificate encCert = null;
    private PrivateKey encKey = null;
        
    /** Sets the complete certificate in the response message.
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert) {
        this.cert=cert;
    }
    /** Gets the response message in the default encoding format.
     * @return the response message in the default encoding format.
     */
    public byte[] getResponseMessage() throws CertificateEncodingException {
            return cert.getEncoded();
    }
    /** Sets the status of the response message.
     * @param status status of the response.
     */
    public void setStatus(int status) {
        this.status = status;
    }
    /** Create encrypts and creates signatures as needed to produce a complete response message. 
     * If needed setSignKeyInfo and setEncKeyInfo must be called before this method.
     * After this is called the response message can be retrieved with getResponseMessage();
     * @return True if signature/encryption was successful, false if it failed, request should not be sent back i failed.
     * @throws IOException If input/output or encoding failed.
     * @throws InvalidKeyException If the key used for signing/encryption is invalid.
     * @throws NoSuchProviderException if there is an error with the Provider.
     * @throws NoSuchAlgorithmException if the signature on the request is done with an unhandled algorithm.
     * @see #setSignKeyInfo()
     * @see #setEncKeyInfo()
     */
    public boolean create() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        boolean ret = false;
        try {
            // Add the issued certificate to the signed portion of the CMS (as signer, degenerate case)
            ArrayList certList = new ArrayList();
            certList.add(cert);
            certList.add(signCert);
            CertStore certs = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
            // Create the signed CMS message
            CMSProcessable msg = null;
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            gen.addSigner(signKey, signCert, CMSSignedDataGenerator.DIGEST_SHA1);
            gen.addCertificatesAndCRLs(certs);
            CMSSignedData s = gen.generate(msg, true, "BC");
            // Envelope the CMS message
            CMSEnvelopedDataGenerator edGen = new CMSEnvelopedDataGenerator();
            edGen.addKeyTransRecipient((X509Certificate)cert);
            CMSEnvelopedData ed = edGen.generate(new CMSProcessableByteArray(s.getEncoded()), 
                    CMSEnvelopedDataGenerator.DES_EDE3_CBC, "BC");
        } catch (InvalidAlgorithmParameterException e) {
            log.error("Error creating CertStore: ", e);
        } catch (CertStoreException e) {
            log.error("Error creating CertStore: ", e);
        } catch (CMSException e) {
            log.error("Error creating CMS message: ", e);
        }
        
        // TODO: done forget status and perhaps failInfo
        // TODO: don't forget sender- and recipientNonce
        
        return ret;
    }
    /** indicates if this message needs recipients public and private key to sign.
     * If this returns true, setSignKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo() {
        return true;
    }
    /** indicates if this message needs recipients public and private key to encrypt.
     * If this returns true, setEncKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireEncKeyInfo() {
        return true;
    }
    /** Sets the public and private key needed to sign the message. Must be set if requireSignKeyInfo() returns true.
     * @see #requireSignKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setSignKeyInfo(X509Certificate cert, PrivateKey key) {
        signCert = cert;
        signKey = key;
    }
    /** Sets the public and private key needed to encrypt the message. Must be set if requireEncKeyInfo() returns true.
     * @see #requireEncKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setEncKeyInfo(X509Certificate cert, PrivateKey key) {
        encCert = cert;
        encKey = key;
    }
}
