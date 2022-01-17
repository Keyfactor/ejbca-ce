package org.ejbca.ui.web.admin.ca;

import java.io.Serializable;
import java.util.List;

public class ItsGeographicRegionGuiWrapper implements Serializable {
    
    private static final long serialVersionUID = 1566978095431644417L;
    
    private String type;
    
    private String name; // circular region or rectangular region 1
    
    private String country; // selected option from valid options
    
    private List<String> validOptions;
    
    private String description; // format and pass it to constructor
    
    private boolean sequentialType;
    
    private String helpText;
    
    public String getCountry() {
        return country;
    }

    public void setCountry(String country) {
        this.country = country;
    }

    public List<String> getValidOptions() {
        return validOptions;
    }

    public void setValidOptions(List<String> validOptions) {
        this.validOptions = validOptions;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public boolean isSequentialType() {
        return sequentialType;
    }

    public void setSequentialType(boolean sequentialType) {
        this.sequentialType = sequentialType;
    }

    public String getHelpText() {
        return helpText;
    }

    public void setHelpText(String helpText) {
        this.helpText = helpText;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }      
    
}