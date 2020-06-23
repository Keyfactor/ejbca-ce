
package org.ejbca.core.protocol.ws.client.gen;

import java.security.PublicKey;
import java.util.List;
import java.util.Map;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for sshRequestMessageWs complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="sshRequestMessageWs"&gt;
 *   &lt;complexContent&gt;
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *       &lt;sequence&gt;
 *         &lt;element name="publicKey" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/&gt;
 *         &lt;element name="keyId" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *         &lt;element name="principals" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="additionalExtensions" type="{http://www.w3.org/2001/XMLSchema}string" maxOccurs="unbounded" minOccurs="0"/&gt;
 *         &lt;element name="criticalOptions"&gt;
 *           &lt;complexType&gt;
 *             &lt;complexContent&gt;
 *               &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                 &lt;sequence&gt;
 *                   &lt;element name="entry" maxOccurs="unbounded" minOccurs="0"&gt;
 *                     &lt;complexType&gt;
 *                       &lt;complexContent&gt;
 *                         &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType"&gt;
 *                           &lt;sequence&gt;
 *                             &lt;element name="key" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *                             &lt;element name="value" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *                           &lt;/sequence&gt;
 *                         &lt;/restriction&gt;
 *                       &lt;/complexContent&gt;
 *                     &lt;/complexType&gt;
 *                   &lt;/element&gt;
 *                 &lt;/sequence&gt;
 *               &lt;/restriction&gt;
 *             &lt;/complexContent&gt;
 *           &lt;/complexType&gt;
 *         &lt;/element&gt;
 *         &lt;element name="comment" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/&gt;
 *       &lt;/sequence&gt;
 *     &lt;/restriction&gt;
 *   &lt;/complexContent&gt;
 * &lt;/complexType&gt;
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "sshRequestMessageWs", propOrder = {
    "publicKey",
    "keyId",
    "principals",
    "additionalExtensions",
    "criticalOptions",
    "comment"
})
public class SshRequestMessageWs {

    private String keyId;
    private String comment;
    private byte[] publicKey;
    private List<String> principals;
    private Map<String, String> criticalOptions;
    private Map<String, byte[]> additionalExtensions;
    
    public SshRequestMessageWs() {
        
    }

    /**
     * Constructs a request message for an SSH certificate
     * 
     * @param keyId the requested key ID
     * @param comment a comment to append to the end of the certificate, can be left bland
     * @param publicKey the public key to be signed, either an encoded Java {@link PublicKey} or a public key in SSH format as a byte array
     * @param principals a list of principals for the certificate. Leaving blank will create a wildcard certificate
     * @param criticalOptions the critical options to use
     * @param additionalExtensions any additional extensions besides those defined in the certificate profile, if allowed
     */
    public SshRequestMessageWs(String keyId, String comment, byte[] publicKey, List<String> principals, Map<String, String> criticalOptions,
            Map<String, byte[]> additionalExtensions) {
        super();
        this.keyId = keyId;
        this.comment = comment;
        this.publicKey = publicKey;
        this.principals = principals;
        this.criticalOptions = criticalOptions;
        this.additionalExtensions = additionalExtensions;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getComment() {
        return comment;
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(byte[] publicKey) {
        this.publicKey = publicKey;
    }

    public List<String> getPrincipals() {
        return principals;
    }

    public void setPrincipals(List<String> principals) {
        this.principals = principals;
    }

    public Map<String, String> getCriticalOptions() {
        return criticalOptions;
    }

    public void setCriticalOptions(Map<String, String> criticalOptions) {
        this.criticalOptions = criticalOptions;
    }

    public Map<String, byte[]> getAdditionalExtensions() {
        return additionalExtensions;
    }

    public void setAdditionalExtensions(Map<String, byte[]> additionalExtensions) {
        this.additionalExtensions = additionalExtensions;
    }

}
