<#-- One template, decided by the actions in the token. An invitation (an
     account with no password) carries UPDATE_PASSWORD and VERIFY_EMAIL; an
     operator reset carries UPDATE_PASSWORD alone. VERIFY_EMAIL alone is an
     address to confirm, never an invitation: the provisioning service confirms
     a changed address through send-verify-email (email-verification.ftl), and
     this branch keeps any other caller from rendering it as "set your
     password". Its subject is still executeActionsSubject, a fixed key. -->
<#import "template.ftl" as layout>
<#assign actions = requiredActions![]>
<#assign verifyOnly = (actions?seq_contains("VERIFY_EMAIL") && !actions?seq_contains("UPDATE_PASSWORD"))>
<#assign invitation = (actions?seq_contains("VERIFY_EMAIL") && actions?seq_contains("UPDATE_PASSWORD"))>
<#assign brand = realmName!properties.brandName!'CELINE'>
<@layout.emailLayout>
<#if verifyOnly>
<h1 style="font-size:22px;margin:0 0 16px;">${msg("recVerifyTitle")}</h1>
<p>${msg("recVerifyIntro", brand)}</p>
<@layout.button href=link label=msg("recVerifyButton")/>
<p>${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}</p>
<p style="color:#6b7280;">${msg("recVerifyIgnore")}</p>
<#elseif invitation>
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
