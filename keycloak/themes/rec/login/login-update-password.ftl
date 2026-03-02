<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('password','password-confirm'); section>
    <#if section = "header">
        ${msg("updatePasswordTitle")}
    <#elseif section = "form">
        <form id="kc-passwd-update-form" action="${url.loginAction}" method="post">
            <input type="text" id="username" name="username" value="${username}" autocomplete="username" readonly="readonly" style="display:none;"/>
            <input type="password" id="password-current" name="password" autocomplete="current-password" style="display:none;"/>

            <div class="form-group">
                <label for="password-new" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("passwordNew")}</span>
                </label>
                <input type="password" id="password-new" name="password-new" class="pf-c-form-control"
                       autofocus autocomplete="new-password"
                       aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                       placeholder="${msg("passwordNew")}"
                />
                <#if messagesPerField.existsError('password')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('password'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <label for="password-confirm" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("passwordConfirm")}</span>
                </label>
                <input type="password" id="password-confirm" name="password-confirm" class="pf-c-form-control"
                       autocomplete="new-password"
                       aria-invalid="<#if messagesPerField.existsError('password-confirm')>true</#if>"
                       placeholder="${msg("passwordConfirm")}"
                />
                <#if messagesPerField.existsError('password-confirm')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('password-confirm'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <#if isAppInitiatedAction??>
                    <input class="pf-c-button pf-m-primary pf-m-block" type="submit" value="${msg("doSubmit")}" />
                    <button class="pf-c-button pf-m-link pf-m-block" type="submit" name="cancel-aia" value="true">${msg("doCancel")}</button>
                <#else>
                    <input class="pf-c-button pf-m-primary pf-m-block" type="submit" value="${msg("doSubmit")}" />
                </#if>
            </div>
        </form>
    </#if>
</@layout.registrationLayout>
