package org.ejbca.ui.web.admin.cainterface;

public class CaInfoProperty {    
    private final String text;
    private final String data;
    
    public CaInfoProperty(final String text, final String data) {
        this.text = text;
        this.data = data;
    }

    public String getText() {
        return text;
    }

    public String getData() {
        return data;
    }
}