
package org.w3._2002._03.xkms_;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for RequestAbstractType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="RequestAbstractType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}MessageAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}ResponseMechanism" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RespondWith" maxOccurs="unbounded" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}PendingNotification" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="OriginalRequestId" type="{http://www.w3.org/2001/XMLSchema}NCName" />
 *       &lt;attribute name="ResponseLimit" type="{http://www.w3.org/2001/XMLSchema}integer" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "RequestAbstractType", propOrder = {
    "responseMechanism",
    "respondWith",
    "pendingNotification"
})
/*@XmlSeeAlso({
    ReissueRequestType.class,
    LocateRequestType.class,
    RevokeRequestType.class,
    RecoverRequestType.class,
    CompoundRequestType.class,
    ValidateRequestType.class,
    PendingRequestType.class,
    RegisterRequestType.class
})*/
public abstract class RequestAbstractType
    extends MessageAbstractType
{

    @XmlElement(name = "ResponseMechanism")
    protected List<String> responseMechanism;
    @XmlElement(name = "RespondWith")
    protected List<String> respondWith;
    @XmlElement(name = "PendingNotification")
    protected PendingNotificationType pendingNotification;
    @XmlAttribute(name = "OriginalRequestId")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "NCName")
    protected String originalRequestId;
    @XmlAttribute(name = "ResponseLimit")
    protected BigInteger responseLimit;

    /**
     * Gets the value of the responseMechanism property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the responseMechanism property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getResponseMechanism().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getResponseMechanism() {
        if (responseMechanism == null) {
            responseMechanism = new ArrayList<String>();
        }
        return this.responseMechanism;
    }

    /**
     * Gets the value of the respondWith property.
     * 
     * <p>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the respondWith property.
     * 
     * <p>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getRespondWith().add(newItem);
     * </pre>
     * 
     * 
     * <p>
     * Objects of the following type(s) are allowed in the list
     * {@link String }
     * 
     * 
     */
    public List<String> getRespondWith() {
        if (respondWith == null) {
            respondWith = new ArrayList<String>();
        }
        return this.respondWith;
    }

    /**
     * Gets the value of the pendingNotification property.
     * 
     * @return
     *     possible object is
     *     {@link PendingNotificationType }
     *     
     */
    public PendingNotificationType getPendingNotification() {
        return pendingNotification;
    }

    /**
     * Sets the value of the pendingNotification property.
     * 
     * @param value
     *     allowed object is
     *     {@link PendingNotificationType }
     *     
     */
    public void setPendingNotification(PendingNotificationType value) {
        this.pendingNotification = value;
    }

    /**
     * Gets the value of the originalRequestId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getOriginalRequestId() {
        return originalRequestId;
    }

    /**
     * Sets the value of the originalRequestId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setOriginalRequestId(String value) {
        this.originalRequestId = value;
    }

    /**
     * Gets the value of the responseLimit property.
     * 
     * @return
     *     possible object is
     *     {@link BigInteger }
     *     
     */
    public BigInteger getResponseLimit() {
        return responseLimit;
    }

    /**
     * Sets the value of the responseLimit property.
     * 
     * @param value
     *     allowed object is
     *     {@link BigInteger }
     *     
     */
    public void setResponseLimit(BigInteger value) {
        this.responseLimit = value;
    }

}
