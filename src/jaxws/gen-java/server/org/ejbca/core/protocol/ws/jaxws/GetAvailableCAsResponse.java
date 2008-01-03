
package org.ejbca.core.protocol.ws.jaxws;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlRootElement(name = "getAvailableCAsResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "getAvailableCAsResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class GetAvailableCAsResponse {

    @XmlElement(name = "return", namespace = "")
    private List<String> _return;

    /**
     * 
     * @return
     *     returns List<String>
     */
    public List<String> get_return() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void set_return(List<String> _return) {
        this._return = _return;
    }

}
