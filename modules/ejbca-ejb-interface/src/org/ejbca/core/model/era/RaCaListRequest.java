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

	@Override
	public int hashCode() {
		return HashCodeBuilder.reflectionHashCode(this);
	}
}
