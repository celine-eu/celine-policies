<#macro registrationLayout bodyClass="" displayInfo=false displayMessage=true displayRequiredFields=false displayWide=false showAnotherWayIfPresent=true>
<!DOCTYPE html>
<html lang="<#if locale??>${locale.currentLanguageTag!'en'}<#else>en</#if>">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="robots" content="noindex, nofollow">
    <meta name="theme-color" content="#0d9488">

    <#if properties.meta?has_content>
        <#list properties.meta?split(' ') as meta>
            <#if meta?contains("==")>
                <#assign metaParts = meta?split("==")>
                <#if metaParts?size gt 1>
                    <meta name="${metaParts[0]}" content="${metaParts[1]}"/>
                </#if>
            </#if>
        </#list>
    </#if>

    <title>${msg("loginTitle",(realm.displayName!''))}</title>

    <link rel="icon" href="${url.resourcesPath}/img/favicon.ico" />

    <#if properties.stylesCommon?has_content>
        <#list properties.stylesCommon?split(' ') as style>
            <link href="${url.resourcesCommonPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>

    <#if properties.styles?has_content>
        <#list properties.styles?split(' ') as style>
            <link href="${url.resourcesPath}/${style}" rel="stylesheet" />
        </#list>
    </#if>

    <#if properties.scripts?has_content>
        <#list properties.scripts?split(' ') as script>
            <script src="${url.resourcesPath}/${script}" type="text/javascript"></script>
        </#list>
    </#if>

    <#if scripts??>
        <#list scripts as script>
            <script src="${script}" type="text/javascript"></script>
        </#list>
    </#if>
</head>

<body class="login-pf ${bodyClass}">
    <div class="login-pf-page">
        <#if realm.internationalizationEnabled?? && realm.internationalizationEnabled && locale?? && locale.supported?? && locale.supported?size gt 1>
            <div id="kc-locale">
                <div id="kc-locale-wrapper">
                    <div id="kc-locale-dropdown" class="menu-button-links">
                        <button tabindex="1" id="kc-current-locale-link" aria-label="${msg("languages")}" aria-haspopup="true" aria-expanded="false" aria-controls="language-switch1">
                            ${locale.current!'English'}
                            <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 9l6 6 6-6"/></svg>
                        </button>
                        <ul role="menu" tabindex="-1" aria-labelledby="kc-current-locale-link" aria-activedescendant="" id="language-switch1">
                            <#list locale.supported as l>
                                <li role="none">
                                    <a role="menuitem" id="language-${l.languageTag}" href="${l.url}">${l.label}</a>
                                </li>
                            </#list>
                        </ul>
                    </div>
                </div>
            </div>
        </#if>

        <div id="kc-content">
            <div id="kc-content-wrapper">
                <!-- Logo -->
                <div id="kc-logo-wrapper">
                    <div id="kc-logo">
                        <span class="kc-logo-text">REC</span>
                    </div>
                </div>

                <!-- Page title -->
                <#if !(auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
                    <#if displayRequiredFields>
                        <div class="subtitle">
                            <span class="subtitle-text">${msg("requiredFields")}</span>
                        </div>
                    </#if>
                <#else>
                    <#if displayRequiredFields>
                        <div class="subtitle">
                            <span class="subtitle-text">${msg("requiredFields")}</span>
                        </div>
                    </#if>
                </#if>

                <header>
                    <#if !(auth?has_content && auth.showUsername() && !auth.showResetCredentials())>
                        <h1 id="kc-page-title"><#nested "header"></h1>
                    <#else>
                        <div id="kc-username" class="pf-c-form">
                            <label id="kc-attempted-username">${auth.attemptedUsername!''}</label>
                            <a id="reset-login" href="${url.loginRestartFlowUrl}">
                                <div class="kc-login-tooltip">
                                    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                                    <span class="kc-tooltip-text">${msg("restartLoginTooltip")}</span>
                                </div>
                            </a>
                        </div>
                    </#if>
                </header>

                <!-- Alerts -->
                <#if displayMessage && message?has_content && (message.type != 'warning' || !isAppInitiatedAction??)>
                    <div class="alert alert-${message.type}">
                        <#if message.type = 'success'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22c5.523 0 10-4.477 10-10S17.523 2 12 2 2 6.477 2 12s4.477 10 10 10z"/><path d="M9 12l2 2 4-4"/></svg>
                        <#elseif message.type = 'warning'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
                        <#elseif message.type = 'error'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg>
                        <#elseif message.type = 'info'>
                            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>
                        </#if>
                        <span class="kc-feedback-text">${kcSanitize(message.summary)?no_esc}</span>
                    </div>
                </#if>

                <!-- Main content -->
                <#nested "form">

                <!-- Social providers -->
                <#if auth?has_content && auth.showTryAnotherWayLink?? && auth.showTryAnotherWayLink() && showAnotherWayIfPresent>
                    <form id="kc-select-try-another-way-form" action="${url.loginAction}" method="post">
                        <div>
                            <input type="hidden" name="tryAnotherWay" value="on"/>
                            <a href="#" id="try-another-way" onclick="document.forms['kc-select-try-another-way-form'].submit();return false;">
                                ${msg("doTryAnotherWay")}
                            </a>
                        </div>
                    </form>
                </#if>

                <#nested "socialProviders">

                <!-- Info section -->
                <#if displayInfo>
                    <div id="kc-info">
                        <div id="kc-info-wrapper">
                            <#nested "info">
                        </div>
                    </div>
                </#if>
            </div>
        </div>

        <!-- Footer -->
        <footer class="pf-c-login__footer">
            <ul class="pf-c-login__footer-list">
                <li><a href="#">${msg("termsText", "Terms")}</a></li>
                <li><a href="#">${msg("privacyText", "Privacy")}</a></li>
            </ul>
        </footer>
    </div>

    <script>
        // Locale dropdown toggle
        document.addEventListener('DOMContentLoaded', function() {
            var localeBtn = document.getElementById('kc-current-locale-link');
            var localeDropdown = document.querySelector('#kc-locale-dropdown ul');
            
            if (localeBtn && localeDropdown) {
                localeDropdown.style.display = 'none';
                
                localeBtn.addEventListener('click', function(e) {
                    e.preventDefault();
                    var isExpanded = localeBtn.getAttribute('aria-expanded') === 'true';
                    localeBtn.setAttribute('aria-expanded', !isExpanded);
                    localeDropdown.style.display = isExpanded ? 'none' : 'block';
                });

                // Close on outside click
                document.addEventListener('click', function(e) {
                    if (!e.target.closest('#kc-locale')) {
                        localeBtn.setAttribute('aria-expanded', 'false');
                        localeDropdown.style.display = 'none';
                    }
                });
            }
        });
    </script>
</body>
</html>
</#macro>
