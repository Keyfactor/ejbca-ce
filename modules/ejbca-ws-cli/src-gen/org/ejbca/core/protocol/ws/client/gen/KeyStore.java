
package org.ejbca.core.protocol.ws.client.gen;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


/**
 * <p>Java class for keyStore complex type.
 * 
 * <p>The following schema fragment specifies the expected content contained within this class.
 * 
 * <pre>
 * &lt;complexType name="keyStore">
 *   &lt;complexContent>
 *     &lt;extension base="{http://ws.protocol.core.ejbca.org/}tokenCertificateResponseWS">
 *       &lt;sequence>
 *         &lt;element name="keystoreData" type="{http://www.w3.org/2001/XMLSchema}base64Binary" minOccurs="0"/>
 *       &lt;/sequence>
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 * 
 * 
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "keyStore", propOrder = {
    "keystoreData"
})
public class KeyStore
    extends TokenCertificateResponseWS
{

    protected byte[] keystoreData;

    /**
     * Gets the value of the keystoreData property.
     * 
     * @return
     *     possible object is
     *     byte[]
     */
    public byte[] getKeystoreData() {
        return keystoreData;
    }

    /**
     * Sets the value of the keystoreData property.
     * 
     * @param value
     *     allowed object is
     *     byte[]
     */
    public void setKeystoreData(byte[] value) {
        this.keystoreData = ((byte[]) value);
    }

}
