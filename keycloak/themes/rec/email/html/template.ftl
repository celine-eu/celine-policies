<#-- The layout every HTML email of this theme is rendered in, including the
     ones inherited from `base`. Inline styles only: most mail clients drop a
     <style> block. Nothing a user or a community entered is printed here. -->
<#macro emailLayout>
<!DOCTYPE html>
<html lang="${locale.language}" dir="${(ltr)?then('ltr','rtl')}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="margin:0;padding:0;background-color:#f4f6f8;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;color:#1f2933;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f6f8;padding:24px 12px;">
<tr><td align="center">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background-color:#ffffff;border-radius:8px;">
<tr><td style="padding:24px 32px;border-bottom:3px solid #0d9488;font-size:20px;font-weight:700;color:#0d9488;">${realmName!properties.brandName!'CELINE'}</td></tr>
<tr><td style="padding:24px 32px;font-size:15px;line-height:1.6;">
<#nested>
</td></tr>
<tr><td style="padding:16px 32px 24px;font-size:12px;line-height:1.5;color:#6b7280;border-top:1px solid #e5e7eb;">
${msg("recFooter", realmName!properties.brandName!'CELINE')}
<#if properties.termsUrl?has_content && properties.termsUrl != "#"> · <a href="${properties.termsUrl}" style="color:#6b7280;">${msg("recTerms")}</a></#if>
<#if properties.privacyUrl?has_content && properties.privacyUrl != "#"> · <a href="${properties.privacyUrl}" style="color:#6b7280;">${msg("recPrivacy")}</a></#if>
</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
</#macro>

<#-- A call-to-action button with the address spelled out under it, for the
     clients that do not render the button. -->
<#macro button href label>
<p style="margin:24px 0;text-align:center;">
<a href="${href}" style="display:inline-block;padding:12px 24px;background-color:#0d9488;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600;">${label}</a>
</p>
<p style="font-size:13px;color:#6b7280;">${msg("recLinkFallback")}<br><a href="${href}" style="color:#0d9488;word-break:break-all;">${href}</a></p>
</#macro>
