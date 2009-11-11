
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for ReissueRequestType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ReissueRequestType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}RequestAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ReissueKeyBinding"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}Authentication"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ProofOfPossession" minOccurs="0"/>
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
@XmlType(name = "ReissueRequestType", propOrder = {
    "reissueKeyBinding",
    "authentication",
    "proofOfPossession"
})
public class ReissueRequestType
    extends RequestAbstractType
{

    @XmlElement(name = "ReissueKeyBinding", required = true)
    protected KeyBindingType reissueKeyBinding;
    @XmlElement(name = "Authentication", required = true)
    protected AuthenticationType authentication;
    @XmlElement(name = "ProofOfPossession")
    protected ProofOfPossessionType proofOfPossession;

    /**
     * Gets the value of the reissueKeyBinding property.
     * 
     * @return
     *     possible object is
     *     {@link KeyBindingType }
     *     
     */
    public KeyBindingType getReissueKeyBinding() {
        return reissueKeyBinding;
    }

    /**
     * Sets the value of the reissueKeyBinding property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyBindingType }
     *     
     */
    public void setReissueKeyBinding(KeyBindingType value) {
        this.reissueKeyBinding = value;
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
     * Gets the value of the proofOfPossession property.
     * 
     * @return
     *     possible object is
     *     {@link ProofOfPossessionType }
     *     
     */
    public ProofOfPossessionType getProofOfPossession() {
        return proofOfPossession;
    }

    /**
     * Sets the value of the proofOfPossession property.
     * 
     * @param value
     *     allowed object is
     *     {@link ProofOfPossessionType }
     *     
     */
    public void setProofOfPossession(ProofOfPossessionType value) {
        this.proofOfPossession = value;
    }

}
