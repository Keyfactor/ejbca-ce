
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for QueryKeyBindingType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="QueryKeyBindingType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}KeyBindingAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}TimeInstant" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "QueryKeyBindingType", propOrder = {
    "timeInstant"
})
public class QueryKeyBindingType
    extends KeyBindingAbstractType
{

    @XmlElement(name = "TimeInstant")
    protected TimeInstantType timeInstant;

    /**
     * Gets the value of the timeInstant property.
     * 
     * @return
     *     possible object is
     *     {@link TimeInstantType }
     *     
     */
    public TimeInstantType getTimeInstant() {
        return timeInstant;
    }

    /**
     * Sets the value of the timeInstant property.
     * 
     * @param value
     *     allowed object is
     *     {@link TimeInstantType }
     *     
     */
    public void setTimeInstant(TimeInstantType value) {
        this.timeInstant = value;
    }

}
