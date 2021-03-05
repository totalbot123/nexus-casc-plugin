package com.weareadaptive.nexus.casc.plugin.internal.config;

import java.util.List;

public class ConfigCore {
    private String baseUrl;
    private String userAgentCustomization;
    private int connectionTimeout;
    private int connectionRetryAttempts;
    private ConfigHttpProxy httpProxy;
    private ConfigHttpProxy httpsProxy;
    private List<String> nonProxyHosts;

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public void setUserAgentCustomization(String userAgentCustomization) {
        this.userAgentCustomization = userAgentCustomization;
    }

    public String getUserAgentCustomization() {
        return this.userAgentCustomization;
    }

    public void setConnectionTimeout(int connectionTimeout){
        this.connectionTimeout = connectionTimeout;
    }

    public int getConnectionTimeout(){
        return this.connectionTimeout;
    }

    public void setConnectionRetryAttempts(int connectionRetryAttempts) {
        this.connectionRetryAttempts = connectionRetryAttempts;
    }

    public int getConnectionRetryAttempts(){
        return this.connectionRetryAttempts;
    }

    public ConfigHttpProxy getHttpProxy() {
        return httpProxy;
    }

    public void setHttpProxy(ConfigHttpProxy httpProxy) {
        this.httpProxy = httpProxy;
    }

    public ConfigHttpProxy getHttpsProxy() {
        return httpsProxy;
    }

    public void setHttpsProxy(ConfigHttpProxy httpsProxy) {
        this.httpsProxy = httpsProxy;
    }

    public List<String> getNonProxyHosts() {
        return nonProxyHosts;
    }

    public void setNonProxyHosts(List<String> nonProxyHosts) {
        this.nonProxyHosts = nonProxyHosts;
    }
}
