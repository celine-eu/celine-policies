<#import "template.ftl" as layout>
<#assign brand = realmName!properties.brandName!'CELINE'>
<@layout.emailLayout>
<h1 style="font-size:22px;margin:0 0 16px;">${msg("recVerifyTitle")}</h1>
<p>${msg("recVerifyIntro", brand)}</p>
<@layout.button href=link label=msg("recVerifyButton")/>
<p>${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}</p>
<p style="color:#6b7280;">${msg("recVerifyIgnore")}</p>
</@layout.emailLayout>
