
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for certificate complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="certificate">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="certificateData" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "certificate", propOrder = {
    "certificateData"
})
public class Certificate {

    protected byte[] certificateData;

    /**
     * Gets the value of the certificateData property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getCertificateData() {
        return certificateData;
    }

    /**
     * Sets the value of the certificateData property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setCertificateData(byte[] value) {
        this.certificateData = ((byte[]) value);
    }

}
