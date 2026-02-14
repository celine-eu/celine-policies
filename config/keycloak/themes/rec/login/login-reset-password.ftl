<#import "template.ftl" as layout>
<@layout.registrationLayout displayInfo=true displayMessage=!messagesPerField.existsError('username'); section>
    <#if section = "header">
        ${msg("emailForgotTitle")}
    <#elseif section = "form">
        <form id="kc-reset-password-form" action="${url.loginAction}" method="post">
            <div class="form-group">
                <label for="username" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">
                        <#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>
                    </span>
                </label>
                <input type="text" id="username" name="username" class="pf-c-form-control" autofocus
                       value="${(auth.attemptedUsername!'')}"
                       aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                       placeholder="<#if !realm.loginWithEmailAllowed>${msg("username")}<#elseif !realm.registrationEmailAsUsername>${msg("usernameOrEmail")}<#else>${msg("email")}</#if>"
                />
                <#if messagesPerField.existsError('username')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('username'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <input class="pf-c-button pf-m-primary pf-m-block" type="submit" value="${msg("doSubmit")}"/>
            </div>
        </form>
    <#elseif section = "info">
        <#if realm.duplicateEmailsAllowed>
            ${msg("emailInstructionUsername")}
        <#else>
            ${msg("emailInstruction")}
        </#if>
        <div id="kc-registration">
            <span><a href="${url.loginUrl}">${msg("backToLogin")}</a></span>
        </div>
    </#if>
</@layout.registrationLayout>
