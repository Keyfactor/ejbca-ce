
package org.w3._2002._03.xkms_;

import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlID;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.w3._2000._09.xmldsig_.KeyInfoType;


/**
 * <p>Java class for KeyBindingAbstractType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="KeyBindingAbstractType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}KeyInfo" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}KeyUsage" maxOccurs="3" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}UseKeyWith" maxOccurs="unbounded" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "KeyBindingAbstractType", propOrder = {
    "keyInfo",
    "keyUsage",
    "useKeyWith"
})
/*@XmlSeeAlso({
    QueryKeyBindingType.class,
    PrototypeKeyBindingType.class,
    UnverifiedKeyBindingType.class
})*/
public abstract class KeyBindingAbstractType {

    @XmlElement(name = "KeyInfo", namespace = "http://www.w3.org/2000/09/xmldsig#")
    protected KeyInfoType keyInfo;
    @XmlElement(name = "KeyUsage")
    protected List<String> keyUsage;
    @XmlElement(name = "UseKeyWith")
    protected List<UseKeyWithType> useKeyWith;
    @XmlAttribute(name = "Id")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;

    /**
     * Gets the value of the keyInfo property.
     * 
     * @return
     *     possible object is
     *     {@link KeyInfoType }
     *     
     */
    public KeyInfoType getKeyInfo() {
        return keyInfo;
    }

    /**
     * Sets the value of the keyInfo property.
     * 
     * @param value
     *     allowed object is
     *     {@link KeyInfoType }
     *     
     */
    public void setKeyInfo(KeyInfoType value) {
        this.keyInfo = value;
    }

    /**
     * Gets the value of the keyUsage property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the keyUsage property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getKeyUsage().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getKeyUsage() {
        if (keyUsage == null) {
            keyUsage = new ArrayList<String>();
        }
        return this.keyUsage;
    }

    /**
     * Gets the value of the useKeyWith property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the useKeyWith property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getUseKeyWith().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link UseKeyWithType }
     * 
     * 
     */
    public List<UseKeyWithType> getUseKeyWith() {
        if (useKeyWith == null) {
            useKeyWith = new ArrayList<UseKeyWithType>();
        }
        return this.useKeyWith;
    }

    /**
     * Gets the value of the id property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setId(String value) {
        this.id = value;
    }

}
