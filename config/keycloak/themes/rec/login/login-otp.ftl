<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('totp'); section>
    <#if section = "header">
        ${msg("doLogIn")}
    <#elseif section = "form">
        <form id="kc-otp-login-form" action="${url.loginAction}" method="post">
            <#if otpLogin.userOtpCredentials?size gt 1>
                <div class="form-group">
                    <label for="selectedCredentialId" class="pf-c-form__label">
                        <span class="pf-c-form__label-text">${msg("loginOtpOneTime")}</span>
                    </label>
                    <select id="selectedCredentialId" name="selectedCredentialId" class="pf-c-form-control">
                        <#list otpLogin.userOtpCredentials as otpCredential>
                            <option value="${otpCredential.id}" <#if otpCredential.id == otpLogin.selectedCredentialId>selected</#if>>
                                ${otpCredential.userLabel}
                            </option>
                        </#list>
                    </select>
                </div>
            </#if>

            <div class="form-group">
                <label for="otp" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("loginOtpOneTime")}</span>
                </label>
                <input id="otp" name="otp" autocomplete="one-time-code" type="text" class="pf-c-form-control otp-input" autofocus
                       aria-invalid="<#if messagesPerField.existsError('totp')>true</#if>"
                       placeholder="000000"
                       inputmode="numeric"
                       pattern="[0-9]*"
                />
                <#if messagesPerField.existsError('totp')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('totp'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <input class="pf-c-button pf-m-primary pf-m-block" name="login" id="kc-login" type="submit" value="${msg("doLogIn")}"/>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
