<#-- Forgot password, started by the participant on the login page. The same
     answer is given whether or not the address exists; this email is only ever
     sent to an address that does. -->
<#import "template.ftl" as layout>
<#assign brand = realmName!properties.brandName!'CELINE'>
<@layout.emailLayout>
<h1 style="font-size:22px;margin:0 0 16px;">${msg("recResetTitle")}</h1>
<p>${msg("recForgotIntro", brand)}</p>
<@layout.button href=link label=msg("recResetButton")/>
<p>${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}</p>
<p style="color:#6b7280;">${msg("recResetIgnore")}</p>
</@layout.emailLayout>
