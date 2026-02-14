<#import "template.ftl" as layout>
<@layout.registrationLayout displayMessage=!messagesPerField.existsError('firstName','lastName','email','username','password','password-confirm'); section>
    <#if section = "header">
        ${msg("registerTitle")}
    <#elseif section = "form">
        <form id="kc-register-form" action="${url.registrationAction}" method="post">
            <div class="form-group">
                <label for="firstName" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("firstName")}</span>
                </label>
                <input type="text" id="firstName" class="pf-c-form-control" name="firstName"
                       value="${(register.formData.firstName!'')}"
                       aria-invalid="<#if messagesPerField.existsError('firstName')>true</#if>"
                       placeholder="${msg("firstName")}"
                />
                <#if messagesPerField.existsError('firstName')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('firstName'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <label for="lastName" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("lastName")}</span>
                </label>
                <input type="text" id="lastName" class="pf-c-form-control" name="lastName"
                       value="${(register.formData.lastName!'')}"
                       aria-invalid="<#if messagesPerField.existsError('lastName')>true</#if>"
                       placeholder="${msg("lastName")}"
                />
                <#if messagesPerField.existsError('lastName')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('lastName'))?no_esc}
                    </span>
                </#if>
            </div>

            <div class="form-group">
                <label for="email" class="pf-c-form__label">
                    <span class="pf-c-form__label-text">${msg("email")}</span>
                </label>
                <input type="email" id="email" class="pf-c-form-control" name="email"
                       value="${(register.formData.email!'')}" autocomplete="email"
                       aria-invalid="<#if messagesPerField.existsError('email')>true</#if>"
                       placeholder="${msg("email")}"
                />
                <#if messagesPerField.existsError('email')>
                    <span class="pf-c-form__helper-text pf-m-error">
                        ${kcSanitize(messagesPerField.get('email'))?no_esc}
                    </span>
                </#if>
            </div>

            <#if !realm.registrationEmailAsUsername>
                <div class="form-group">
                    <label for="username" class="pf-c-form__label">
                        <span class="pf-c-form__label-text">${msg("username")}</span>
                    </label>
                    <input type="text" id="username" class="pf-c-form-control" name="username"
                           value="${(register.formData.username!'')}" autocomplete="username"
                           aria-invalid="<#if messagesPerField.existsError('username')>true</#if>"
                           placeholder="${msg("username")}"
                    />
                    <#if messagesPerField.existsError('username')>
                        <span class="pf-c-form__helper-text pf-m-error">
                            ${kcSanitize(messagesPerField.get('username'))?no_esc}
                        </span>
                    </#if>
                </div>
            </#if>

            <#if passwordRequired??>
                <div class="form-group">
                    <label for="password" class="pf-c-form__label">
                        <span class="pf-c-form__label-text">${msg("password")}</span>
                    </label>
                    <input type="password" id="password" class="pf-c-form-control" name="password"
                           autocomplete="new-password"
                           aria-invalid="<#if messagesPerField.existsError('password','password-confirm')>true</#if>"
                           placeholder="${msg("password")}"
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
                    <input type="password" id="password-confirm" class="pf-c-form-control" name="password-confirm"
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
            </#if>

            <#if recaptchaRequired??>
                <div class="form-group">
                    <div class="g-recaptcha" data-size="normal" data-sitekey="${recaptchaSiteKey}"></div>
                </div>
            </#if>

            <div class="form-group">
                <input class="pf-c-button pf-m-primary pf-m-block" type="submit" value="${msg("doRegister")}"/>
            </div>
        </form>
    <#elseif section = "info">
        <div id="kc-registration">
            <span>${msg("alreadyHaveAccount")} <a href="${url.loginUrl}">${msg("doLogIn")}</a></span>
        </div>
    </#if>
</@layout.registrationLayout>
