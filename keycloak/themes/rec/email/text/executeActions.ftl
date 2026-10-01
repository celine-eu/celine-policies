<#ftl output_format="plainText">
<#-- VERIFY_EMAIL alone is an address to confirm, never an invitation; see html/executeActions.ftl. -->
<#assign actions = requiredActions![]>
<#assign verifyOnly = (actions?seq_contains("VERIFY_EMAIL") && !actions?seq_contains("UPDATE_PASSWORD"))>
<#assign invitation = (actions?seq_contains("VERIFY_EMAIL") && actions?seq_contains("UPDATE_PASSWORD"))>
<#assign brand = realmName!properties.brandName!'CELINE'>
<#if verifyOnly>
${msg("recVerifyTitle")}

${msg("recVerifyIntro", brand)}

${msg("recVerifyButton")}:
${link}

${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}

${msg("recVerifyIgnore")}
<#elseif invitation>
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
