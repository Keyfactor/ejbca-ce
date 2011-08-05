
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for StatusType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="StatusType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ValidReason" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}IndeterminateReason" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}InvalidReason" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="StatusValue" use="required" type="{http://www.w3.org/2002/03/xkms#}KeyBindingEnum" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "StatusType", propOrder = {
    "validReason",
    "indeterminateReason",
    "invalidReason"
})
public class StatusType {

    @XmlElement(name = "ValidReason")
    protected List<String> validReason;
    @XmlElement(name = "IndeterminateReason")
    protected List<String> indeterminateReason;
    @XmlElement(name = "InvalidReason")
    protected List<String> invalidReason;
    @XmlAttribute(name = "StatusValue", required = true)
    protected String statusValue;

    /**
     * Gets the value of the validReason property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the validReason property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getValidReason().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getValidReason() {
        if (validReason == null) {
            validReason = new ArrayList<String>();
        }
        return this.validReason;
    }

    /**
     * Gets the value of the indeterminateReason property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the indeterminateReason property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getIndeterminateReason().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getIndeterminateReason() {
        if (indeterminateReason == null) {
            indeterminateReason = new ArrayList<String>();
        }
        return this.indeterminateReason;
    }

    /**
     * Gets the value of the invalidReason property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the invalidReason property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getInvalidReason().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getInvalidReason() {
        if (invalidReason == null) {
            invalidReason = new ArrayList<String>();
        }
        return this.invalidReason;
    }

    /**
     * Gets the value of the statusValue property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getStatusValue() {
        return statusValue;
    }

    /**
     * Sets the value of the statusValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setStatusValue(String value) {
        this.statusValue = value;
    }

}
