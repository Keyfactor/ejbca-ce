
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

import org.w3._2000._09.xmldsig_.SignatureType;


/**
 * <p>Java class for MessageAbstractType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="MessageAbstractType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}Signature" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}MessageExtension" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}OpaqueClientData" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Id" use="required" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *       &lt;attribute name="Service" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *       &lt;attribute name="Nonce" type="{http://www.w3.org/2001/XMLSchema}base64Binary" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "MessageAbstractType", propOrder = {
    "signature",
    "messageExtension",
    "opaqueClientData"
})
/*@XmlSeeAlso({
    ResultType.class,
    RequestAbstractType.class
})*/
public abstract class MessageAbstractType {

    @XmlElement(name = "Signature", namespace = "http://www.w3.org/2000/09/xmldsig#")
    protected SignatureType signature;
    @XmlElement(name = "MessageExtension")
    protected List<MessageExtensionAbstractType> messageExtension;
    @XmlElement(name = "OpaqueClientData")
    protected OpaqueClientDataType opaqueClientData;
    @XmlAttribute(name = "Id", required = true)
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;
    @XmlAttribute(name = "Service", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String service;
    @XmlAttribute(name = "Nonce")
    protected byte[] nonce;

    /**
     * Gets the value of the signature property.
     * 
     * @return
     *     possible object is
     *     {@link SignatureType }
     *     
     */
    public SignatureType getSignature() {
        return signature;
    }

    /**
     * Sets the value of the signature property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignatureType }
     *     
     */
    public void setSignature(SignatureType value) {
        this.signature = value;
    }

    /**
     * Gets the value of the messageExtension property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the messageExtension property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getMessageExtension().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link MessageExtensionAbstractType }
     * 
     * 
     */
    public List<MessageExtensionAbstractType> getMessageExtension() {
        if (messageExtension == null) {
            messageExtension = new ArrayList<MessageExtensionAbstractType>();
        }
        return this.messageExtension;
    }

    /**
     * Gets the value of the opaqueClientData property.
     * 
     * @return
     *     possible object is
     *     {@link OpaqueClientDataType }
     *     
     */
    public OpaqueClientDataType getOpaqueClientData() {
        return opaqueClientData;
    }

    /**
     * Sets the value of the opaqueClientData property.
     * 
     * @param value
     *     allowed object is
     *     {@link OpaqueClientDataType }
     *     
     */
    public void setOpaqueClientData(OpaqueClientDataType value) {
        this.opaqueClientData = value;
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

    /**
     * Gets the value of the service property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getService() {
        return service;
    }

    /**
     * Sets the value of the service property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setService(String value) {
        this.service = value;
    }

    /**
     * Gets the value of the nonce property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Sets the value of the nonce property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setNonce(byte[] value) {
        this.nonce = ((byte[]) value);
    }

}
