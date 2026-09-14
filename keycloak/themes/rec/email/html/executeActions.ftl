<#-- One template, two emails, decided by the actions in the token.
     VERIFY_EMAIL rides only with an invitation (an account with no password);
     an operator reset carries UPDATE_PASSWORD alone. -->
<#import "template.ftl" as layout>
<#assign invitation = (requiredActions?? && requiredActions?seq_contains("VERIFY_EMAIL"))>
<#assign brand = realmName!properties.brandName!'CELINE'>
<@layout.emailLayout>
<#if invitation>
<h1 style="font-size:22px;margin:0 0 16px;">${msg("recInvitationTitle", brand)}</h1>
<p>${msg("recInvitationIntro", brand)}</p>
<@layout.button href=link label=msg("recInvitationButton")/>
<p>${msg("recInvitationAfter")}</p>
<p>${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}</p>
<p style="color:#6b7280;">${msg("recInvitationIgnore")}</p>
<#else>
<h1 style="font-size:22px;margin:0 0 16px;">${msg("recResetTitle")}</h1>
<p>${msg("recResetIntro", brand)}</p>
<@layout.button href=link label=msg("recResetButton")/>
<p>${msg("recResetAfter")}</p>
<p>${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}</p>
<p style="color:#6b7280;">${msg("recResetIgnore")}</p>
</#if>
</@layout.emailLayout>
