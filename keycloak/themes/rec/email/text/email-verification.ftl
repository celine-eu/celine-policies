<#ftl output_format="plainText">
<#assign brand = realmName!properties.brandName!'CELINE'>
${msg("recVerifyTitle")}

${msg("recVerifyIntro", brand)}

${msg("recVerifyButton")}:
${link}

${msg("recLinkExpiry", linkExpirationFormatter(linkExpiration))}

${msg("recVerifyIgnore")}

--
${msg("recFooter", brand)}
