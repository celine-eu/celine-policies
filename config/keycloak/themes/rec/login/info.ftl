<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=false; section>
    <#if section = "header">
        <#if messageHeader??>
            ${messageHeader}
        <#else>
            ${message.summary}
        </#if>
    <#elseif section = "form">
        <div id="kc-info-message">
            <#if message.summary??>
                <div class="alert alert-info">
                    <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                        <circle cx="12" cy="12" r="10"/>
                        <line x1="12" y1="16" x2="12" y2="12"/>
                        <line x1="12" y1="8" x2="12.01" y2="8"/>
                    </svg>
                    <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
                </div>
            </#if>

            <#if requiredActions??>
                <p style="margin-top: var(--space-md);">
                    <b>${msg("requiredAction")}: </b>
                    <#list requiredActions as reqAction>
                        ${msg("requiredAction.${reqAction}")}<#sep>, </#sep>
                    </#list>
                </p>
            </#if>

            <#if skipLink??>
            <#else>
                <#if pageRedirectUri?has_content>
                    <p style="margin-top: var(--space-lg); text-align: center;">
                        <a href="${pageRedirectUri}" class="pf-c-button pf-m-primary">${kcSanitize(msg("backToApplication"))?no_esc}</a>
                    </p>
                <#elseif actionUri?has_content>
                    <p style="margin-top: var(--space-lg); text-align: center;">
                        <a href="${actionUri}" class="pf-c-button pf-m-primary">${kcSanitize(msg("proceedWithAction"))?no_esc}</a>
                    </p>
                <#elseif (client.baseUrl)?has_content>
                    <p style="margin-top: var(--space-lg); text-align: center;">
                        <a href="${client.baseUrl}" class="pf-c-button pf-m-primary">${kcSanitize(msg("backToApplication"))?no_esc}</a>
                    </p>
                </#if>
            </#if>
        </div>
    </#if>
</@layout.registrationLayout>
