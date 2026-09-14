<#ftl output_format="plainText">
<#assign invitation = (requiredActions?? && requiredActions?seq_contains("VERIFY_EMAIL"))>
<#assign brand = realmName!properties.brandName!'CELINE'>
<#if invitation>
${msg("recInvitationTitle", brand)}

${msg("recInvitationIntro", brand)}

${msg("recInvitationButton")}:
${link}

${msg("recInvitationAfter")}

${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}

${msg("recInvitationIgnore")}
<#else>
${msg("recResetTitle")}

${msg("recResetIntro", brand)}

${msg("recResetButton")}:
${link}

${msg("recResetAfter")}

${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}

${msg("recResetIgnore")}
</#if>

--
${msg("recFooter", brand)}
