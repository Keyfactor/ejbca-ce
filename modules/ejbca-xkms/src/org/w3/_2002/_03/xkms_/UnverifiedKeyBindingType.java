
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for UnverifiedKeyBindingType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="UnverifiedKeyBindingType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}KeyBindingAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ValidityInterval" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "UnverifiedKeyBindingType", propOrder = {
    "validityInterval"
})
/*@XmlSeeAlso({
    KeyBindingType.class
})*/
public class UnverifiedKeyBindingType
    extends KeyBindingAbstractType
{

    @XmlElement(name = "ValidityInterval")
    protected ValidityIntervalType validityInterval;

    /**
     * Gets the value of the validityInterval property.
     * 
     * @return
     *     possible object is
     *     {@link ValidityIntervalType }
     *     
     */
    public ValidityIntervalType getValidityInterval() {
        return validityInterval;
    }

    /**
     * Sets the value of the validityInterval property.
     * 
     * @param value
     *     allowed object is
     *     {@link ValidityIntervalType }
     *     
     */
    public void setValidityInterval(ValidityIntervalType value) {
        this.validityInterval = value;
    }

}
