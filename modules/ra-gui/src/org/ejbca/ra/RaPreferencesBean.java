package org.ejbca.ra;

import java.io.Serializable;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.ejb.EJB;
import javax.faces.bean.ManagedBean;
import javax.faces.bean.ManagedProperty;
import javax.faces.bean.ViewScoped;
import javax.faces.context.FacesContext;

import org.apache.log4j.Logger;
import org.cesecore.config.RaStyleInfo;
import org.ejbca.core.ejb.ra.raadmin.AdminPreferenceSessionLocal;
import org.ejbca.core.model.era.RaMasterApiProxyBeanLocal;

@ManagedBean
@ViewScoped
public class RaPreferencesBean implements Serializable {

    private static final long serialVersionUID = 1L;
    private static final Logger log = Logger.getLogger(RaPreferencesBean.class);

    private boolean renderLanguageInfo = false;

    private RaStyleInfo currentStyle = null;

    public boolean isRenderLanguageInfo() {
        return renderLanguageInfo;
    }

    public void setRenderLanguageInfo(boolean renderLanguageInfo) {
        this.renderLanguageInfo = renderLanguageInfo;
    }

    @EJB
    private AdminPreferenceSessionLocal adminPreferenceSession;

    @ManagedProperty(value = "#{raLocaleBean}")
    private RaLocaleBean raLocaleBean;
    public void setRaLocaleBean(final RaLocaleBean raLocaleBean) {
        this.raLocaleBean = raLocaleBean;
    }

    @ManagedProperty(value="#{raAuthenticationBean}")
    private RaAuthenticationBean raAuthenticationBean;
    public void setRaAuthenticationBean(RaAuthenticationBean raAuthenticationBean) {
        this.raAuthenticationBean = raAuthenticationBean;
    }

    public List<Locale> getLocales() {
        return raLocaleBean.getSupportedLocales();
    }

    public RaStyleInfo getCurrentStyle() {
        return this.currentStyle;
    }

    public Locale getCurrentLocale() {
        return raLocaleBean.getLocale();
    }

    public void setCurrentLocale(final Locale locale) {
        if(locale == null) {
            return;
        }
        raLocaleBean.setLocale(locale);
    }

    public void setCurrentStyle(final RaStyleInfo currentStyle) {
        if(currentStyle == null) {
            return;
        }
        log.info("Setting the current style to " + currentStyle.getArchiveName());
        this.currentStyle = currentStyle;
    }

    public List<RaStyleInfo> getStyles() {
        List<RaStyleInfo> styleInfos = adminPreferenceSession.getAvailableRaStyleInfos(raAuthenticationBean.getAuthenticationToken());
        if (styleInfos == null || styleInfos.isEmpty()) {
            return null;
        } else {
            return styleInfos;
        }
    }

    public void updatePreferences(final Locale locale, final RaStyleInfo style) {
        this.setCurrentLocale(locale);
        
        this.setCurrentStyle(style);
    }

    public String reset() {
        String viewId = FacesContext.getCurrentInstance().getViewRoot().getViewId();
        return viewId+"?faces-redirect=true";
    }

    public void toggleShowLanguageInfo() {
        renderLanguageInfo = !renderLanguageInfo;
    }

}
