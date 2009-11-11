
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for RecoverRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RecoverRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}RequestAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RecoverKeyBinding"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}Authentication"/>
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
@XmlType(name = "RecoverRequestType", propOrder = {
    "recoverKeyBinding",
    "authentication"
})
public class RecoverRequestType
    extends RequestAbstractType
{

    @XmlElement(name = "RecoverKeyBinding", required = true)
    protected KeyBindingType recoverKeyBinding;
    @XmlElement(name = "Authentication", required = true)
    protected AuthenticationType authentication;

    /**
     * Gets the value of the recoverKeyBinding property.
     * 
     * @return
     *     possible object is
     *     {@link KeyBindingType }
     *     
     */
    public KeyBindingType getRecoverKeyBinding() {
        return recoverKeyBinding;
    }

    /**
     * Sets the value of the recoverKeyBinding property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyBindingType }
     *     
     */
    public void setRecoverKeyBinding(KeyBindingType value) {
        this.recoverKeyBinding = value;
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

}
