package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

/** A response message consisting of a single X509 Certificate.
*
* @version  $Id: X509ResponseMessage.java,v 1.4 2003-06-15 11:58:32 anatom Exp $
*/
public class  X509ResponseMessage implements IResponseMessage {

    /** Certificate to be in response message,
     */
    private Certificate cert = null;
    /** status for the response
     */
    private int status = 0;
    
    /** Sets the complete certificate in the response message.
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert) {
        this.cert=cert;
    }
    /** Gets the response message in the default encoding format.
     * @return the response message in the default encoding format.
     */
    public byte[] getResponseMessage() throws IOException, CertificateEncodingException {
            return cert.getEncoded();
    }
    /** Sets the status of the response message.
     * @param status status of the response.
     */
    public void setStatus(int status) {
        this.status = status;
    }
    /** Sets info about reason for failure.
     * @param failInfo reason for failure.
     */
    public void setFailInfo(String failInfo) {
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
        // Nothing needs to be done here
        return true;
    }
    /** indicates if this message needs recipients public and private key to sign.
     * If this returns true, setSignKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo() {
        return false;
    }
    /** indicates if this message needs recipients public and private key to encrypt.
     * If this returns true, setEncKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireEncKeyInfo() {
        return false;
    }
    /** Sets the public and private key needed to sign the message. Must be set if requireSignKeyInfo() returns true.
     * @see #requireSignKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setSignKeyInfo(X509Certificate cert, PrivateKey key) {
    }
    /** Sets the public and private key needed to encrypt the message. Must be set if requireEncKeyInfo() returns true.
     * @see #requireEncKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setEncKeyInfo(X509Certificate cert, PrivateKey key) {
    }
}
