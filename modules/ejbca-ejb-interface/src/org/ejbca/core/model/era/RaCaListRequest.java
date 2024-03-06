package org.ejbca.core.model.era;

import org.apache.commons.lang.builder.HashCodeBuilder;

import java.io.Serializable;

public class RaCaListRequest implements Serializable {

	private static final long serialVersionUID = 1L;
	private boolean includeExternal;

	public boolean isIncludeExternal() {
		return includeExternal;
	}

	public void setIncludeExternal(boolean includeExternal) {
		this.includeExternal = includeExternal;
	}
	
	/* Required for CaRestResourceUnitTest. Otherwise EasyMock does not recognize the method call with this object as parameter. */
    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (obj == null)
            return false;
        if (getClass() != obj.getClass())
            return false;
        RaCaListRequest other = (RaCaListRequest) obj;
        if (includeExternal != other.includeExternal)
            return false;
        return true;
    }

	@Override
	public int hashCode() {
		return HashCodeBuilder.reflectionHashCode(this);
	}
	
}
