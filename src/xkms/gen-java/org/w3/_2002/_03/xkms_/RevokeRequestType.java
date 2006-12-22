
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RevokeRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RevokeRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}RequestAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RevokeKeyBinding"/>
 *         &lt;choice>
 *           &lt;element ref="{http://www.w3.org/2002/03/xkms#}Authentication"/>
 *           &lt;element ref="{http://www.w3.org/2002/03/xkms#}RevocationCode"/>
 *         &lt;/choice>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlRootElement
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RevokeRequestType", propOrder = {
    "revokeKeyBinding",
    "authentication",
    "revocationCode"
})
public class RevokeRequestType
    extends RequestAbstractType
{

    @XmlElement(name = "RevokeKeyBinding", required = true)
    protected KeyBindingType revokeKeyBinding;
    @XmlElement(name = "Authentication")
    protected AuthenticationType authentication;
    @XmlElement(name = "RevocationCode")
    protected byte[] revocationCode;

    /**
     * Gets the value of the revokeKeyBinding property.
     * 
     * @return
     *     possible object is
     *     {@link KeyBindingType }
     *     
     */
    public KeyBindingType getRevokeKeyBinding() {
        return revokeKeyBinding;
    }

    /**
     * Sets the value of the revokeKeyBinding property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyBindingType }
     *     
     */
    public void setRevokeKeyBinding(KeyBindingType value) {
        this.revokeKeyBinding = value;
    }

    /**
     * Gets the value of the authentication property.
     * 
     * @return
     *     possible object is
     *     {@link AuthenticationType }
     *     
     */
    public AuthenticationType getAuthentication() {
        return authentication;
    }

    /**
     * Sets the value of the authentication property.
     * 
     * @param value
     *     allowed object is
     *     {@link AuthenticationType }
     *     
     */
    public void setAuthentication(AuthenticationType value) {
        this.authentication = value;
    }

    /**
     * Gets the value of the revocationCode property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getRevocationCode() {
        return revocationCode;
    }

    /**
     * Sets the value of the revocationCode property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setRevocationCode(byte[] value) {
        this.revocationCode = ((byte[]) value);
    }

}
