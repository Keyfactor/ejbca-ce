
package org.ejbca.core.protocol.ws.jaxws;

import java.util.List;
import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import org.ejbca.core.protocol.ws.objects.UserDataSourceVOWS;

@XmlRootElement(name = "fetchUserDataResponse", namespace = "http://ws.protocol.core.ejbca.org/")
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "fetchUserDataResponse", namespace = "http://ws.protocol.core.ejbca.org/")
public class FetchUserDataResponse {

    @XmlElement(name = "return", namespace = "")
    private List<UserDataSourceVOWS> _return;

    /**
     * 
     * @return
     *     returns List<UserDataSourceVOWS>
     */
    public List<UserDataSourceVOWS> get_return() {
        return this._return;
    }

    /**
     * 
     * @param _return
     *     the value for the _return property
     */
    public void set_return(List<UserDataSourceVOWS> _return) {
        this._return = _return;
    }

}
