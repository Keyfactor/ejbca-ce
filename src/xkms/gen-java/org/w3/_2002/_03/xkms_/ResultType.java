
package org.w3._2002._03.xkms_;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlSchemaType;
import javax.xml.bind.annotation.XmlType;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;

import org.w3._2000._09.xmldsig_.SignatureValueType;


/**
 * <p>Java class for ResultType complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="ResultType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2002/03/xkms#}MessageAbstractType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2002/03/xkms#}RequestSignatureValue" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="ResultMajor" use="required" type="{http://www.w3.org/2002/03/xkms#}ResultMajorOpenEnum" />
 *       &lt;attribute name="ResultMinor" type="{http://www.w3.org/2002/03/xkms#}ResultMinorOpenEnum" />
 *       &lt;attribute name="RequestId" type="{http://www.w3.org/2001/XMLSchema}NCName" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "ResultType", propOrder = {
    "requestSignatureValue"
})
/*@XmlSeeAlso({
    ReissueResultType.class,
    StatusResultType.class,
    RevokeResultType.class,
    CompoundResultType.class,
    ValidateResultType.class,
    RecoverResultType.class,
    RegisterResultType.class,
    LocateResultType.class
})*/
public class ResultType
    extends MessageAbstractType
{

    @XmlElement(name = "RequestSignatureValue")
    protected SignatureValueType requestSignatureValue;
    @XmlAttribute(name = "ResultMajor", required = true)
    protected String resultMajor;
    @XmlAttribute(name = "ResultMinor")
    protected String resultMinor;
    @XmlAttribute(name = "RequestId")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlSchemaType(name = "NCName")
    protected String requestId;

    /**
     * Gets the value of the requestSignatureValue property.
     * 
     * @return
     *     possible object is
     *     {@link SignatureValueType }
     *     
     */
    public SignatureValueType getRequestSignatureValue() {
        return requestSignatureValue;
    }

    /**
     * Sets the value of the requestSignatureValue property.
     * 
     * @param value
     *     allowed object is
     *     {@link SignatureValueType }
     *     
     */
    public void setRequestSignatureValue(SignatureValueType value) {
        this.requestSignatureValue = value;
    }

    /**
     * Gets the value of the resultMajor property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getResultMajor() {
        return resultMajor;
    }

    /**
     * Sets the value of the resultMajor property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setResultMajor(String value) {
        this.resultMajor = value;
    }

    /**
     * Gets the value of the resultMinor property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getResultMinor() {
        return resultMinor;
    }

    /**
     * Sets the value of the resultMinor property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setResultMinor(String value) {
        this.resultMinor = value;
    }

    /**
     * Gets the value of the requestId property.
     * 
     * @return
     *     possible object is
     *     {@link String }
     *     
     */
    public String getRequestId() {
        return requestId;
    }

    /**
     * Sets the value of the requestId property.
     * 
     * @param value
     *     allowed object is
     *     {@link String }
     *     
     */
    public void setRequestId(String value) {
        this.requestId = value;
    }

}
