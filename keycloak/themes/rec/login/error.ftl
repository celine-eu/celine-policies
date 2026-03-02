<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        ${msg("errorTitle")}
    <#elseif section = "form">
        <div id="kc-error-message">
            <div class="alert alert-error">
                <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <circle cx="12" cy="12" r="10"/>
                    <line x1="15" y1="9" x2="9" y2="15"/>
                    <line x1="9" y1="9" x2="15" y2="15"/>
                </svg>
                <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
            </div>

            <#if skipLink??>
            <#else>
                <#if client?? && client.baseUrl?has_content>
                    <p style="margin-top: var(--space-lg); text-align: center;">
                        <a id="backToApplication" href="${client.baseUrl}" class="pf-c-button pf-m-link">${kcSanitize(msg("backToApplication"))?no_esc}</a>
                    </p>
                </#if>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
