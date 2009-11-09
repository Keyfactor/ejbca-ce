
package org.ejbca.core.protocol.ws.jaxws;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "getAvailableCertificateProfilesResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getAvailableCertificateProfilesResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class GetAvailableCertificateProfilesResponse {

    @XmlElement(name = "return", namespace = "", nillable = true)
    private org.ejbca.core.protocol.ws.objects.NameAndId[] _return;

    /**
     * 
     * @return
     *     returns NameAndId[]
     */
    public org.ejbca.core.protocol.ws.objects.NameAndId[] getReturn() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void setReturn(org.ejbca.core.protocol.ws.objects.NameAndId[] _return) {
        this._return = _return;
    }

}
