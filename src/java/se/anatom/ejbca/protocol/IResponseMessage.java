package se.anatom.ejbca.protocol;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

/** Base interface for response messages sent from the CA.
* Implementors of this interface must also implement Serializable if they are to be sent to any EJB bussiness methods.
* Example:
* <code>
* ResponseMessage resp = new ResponseMessage();
* resp.setCertificate(cert);
* resp.setStatus(OK);
* if (resp.requireSignKeyInfo()) { resp.setSignKeyInfo(signcert,signkey) };
* if (resp.requireEncKeyInfo()) { resp.setEncKeyInfo(enccert,enckey) };
* resp.create();
* byte[] responseMessage = resp.getResponseMessage();
* </code>
*
* @version  $Id: IResponseMessage.java,v 1.3 2003-06-14 11:29:10 anatom Exp $
*/
public interface  IResponseMessage {

    public final int STATUS_OK = 0;
    public final int STATUS_FAILED = 1;
    
    /** Sets the complete certificate in the response message.
     * @param cert certificate in the response message.
     */
    public void setCertificate(Certificate cert);
    /** Gets the response message in the default encoding format.
     * @return the response message in the default encoding format.
     */
    public byte[] getResponseMessage() throws IOException, CertificateEncodingException;
    /** Sets the status of the response message.
     * @param status status of the response.
     */
    public void setStatus(int status);
    /** Sets info about reason for failure.
     * @param failInfo reason for failure.
     */
    public void setFailInfo(String failInfo);
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
    public boolean create() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException;
    /** indicates if this message needs recipients public and private key to sign.
     * If this returns true, setSignKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireSignKeyInfo();
    /** indicates if this message needs recipients public and private key to encrypt.
     * If this returns true, setEncKeyInfo() should be called.
     * @return True if public and private key is needed.
     */
    public boolean requireEncKeyInfo();
    /** Sets the public and private key needed to sign the message. Must be set if requireSignKeyInfo() returns true.
     * @see #requireSignKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setSignKeyInfo(X509Certificate cert, PrivateKey key);
    /** Sets the public and private key needed to encrypt the message. Must be set if requireEncKeyInfo() returns true.
     * @see #requireEncKeyInfo()
     *
     * @param cert certificate containing the public key.
     * @param key private key.
     */
    public void setEncKeyInfo(X509Certificate cert, PrivateKey key);
}
