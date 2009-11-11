
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for AuthenticationType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="AuthenticationType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}KeyBindingAuthentication" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}NotBoundAuthentication" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "AuthenticationType", propOrder = {
    "keyBindingAuthentication",
    "notBoundAuthentication"
})
public class AuthenticationType {

    @XmlElement(name = "KeyBindingAuthentication")
    protected KeyBindingAuthenticationType keyBindingAuthentication;
    @XmlElement(name = "NotBoundAuthentication")
    protected NotBoundAuthenticationType notBoundAuthentication;

    /**
     * Gets the value of the keyBindingAuthentication property.
     * 
     * @return
     *     possible object is
     *     {@link KeyBindingAuthenticationType }
     *     
     */
    public KeyBindingAuthenticationType getKeyBindingAuthentication() {
        return keyBindingAuthentication;
    }

    /**
     * Sets the value of the keyBindingAuthentication property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyBindingAuthenticationType }
     *     
     */
    public void setKeyBindingAuthentication(KeyBindingAuthenticationType value) {
        this.keyBindingAuthentication = value;
    }

    /**
     * Gets the value of the notBoundAuthentication property.
     * 
     * @return
     *     possible object is
     *     {@link NotBoundAuthenticationType }
     *     
     */
    public NotBoundAuthenticationType getNotBoundAuthentication() {
        return notBoundAuthentication;
    }

    /**
     * Sets the value of the notBoundAuthentication property.
     * 
     * @param value
     *     allowed object is
     *     {@link NotBoundAuthenticationType }
     *     
     */
    public void setNotBoundAuthentication(NotBoundAuthenticationType value) {
        this.notBoundAuthentication = value;
    }

}
