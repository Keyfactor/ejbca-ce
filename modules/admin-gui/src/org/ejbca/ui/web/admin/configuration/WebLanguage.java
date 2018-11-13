package org.ejbca.ui.web.admin.configuration;

/*
* DTO class for holding information and properties about one language
*/
public class WebLanguage {
    
    private int id;
    private String englishName;
    private String nativeName;
    private String abbreviation;
    
    public WebLanguage(final int id, final String englishName, final String nativeName, final String abbreviation) {
        this.id = id;
        this.englishName = englishName;
        this.nativeName = nativeName;
        this.abbreviation = abbreviation;
    }    
    
    public int getId() {
        return id;
    }
    public void setId(final int id) {
        this.id = id;
    }
    public String getEnglishName() {
        return englishName;
    }
    public void setEnglishName(final String englishName) {
        this.englishName = englishName;
    }
    public String getNativeName() {
        return nativeName;
    }
    public void setNativeName(final String nativeName) {
        this.nativeName = nativeName;
    }
    public String getAbbreviation() {
        return abbreviation;
    }
    public void setAbbreviation(final String abbreviation) {
        this.abbreviation = abbreviation;
    }

    @Override
    public String toString() {
        return englishName + " - " + nativeName + " [" + abbreviation + "]";
    }
}