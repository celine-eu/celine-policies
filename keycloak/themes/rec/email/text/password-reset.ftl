<#ftl output_format="plainText">
<#assign brand = realmName!properties.brandName!'CELINE'>
${msg("recResetTitle")}

${msg("recForgotIntro", brand)}

${msg("recResetButton")}:
${link}

${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}

${msg("recResetIgnore")}

--
${msg("recFooter", brand)}
