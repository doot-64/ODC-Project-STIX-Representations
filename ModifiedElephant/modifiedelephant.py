from stix2.v21 import *
from datetime import datetime

if __name__ == '__main__':
    modifiedElephant = ThreatActor(
        name = "ModifiedElephant",
        description = "ModifiedElephant is responsible for targeted attacks on human rights activists, human rights defenders, academics, and lawyers across India with the objective of planting incriminating digital evidence",
        goals = ["long-term surveillance to incriminate the target in specific crimes"],
    )

    victims = Identity(
        name = "Human right activists and academics",
        description = "ModifiedElephant is responsible for targeted attacks on human rights activists, human rights defenders, academics, and lawyers across India with the objective of planting incriminating digital evidence."
    )

    meTargetsVictims = Relationship(
        modifiedElephant,
        'targets',
        victims,
    )

    india = Location(
        name = "India",
        country = "India",
        description = "ModifiedElephant is responsible for targeted attacks on human rights activists, human rights defenders, academics, and lawyers across India with the objective of planting incriminating digital evidence."
    )

    victimsLocatedinIndia = Relationship(
        victims,
        'located-at',
        india,
    )

    modifiedElephantTargetsIndia = Relationship(
        modifiedElephant,
        'located-at',
        india,
    )

    plantingCampaigns = Campaign(
        name = "Planting Phishing Campaign",
        description = "Throughout the last decade, ModifiedElephant operators sought to infect their targets via spearphishing emails with malicious file attachments, with their techniques evolving over time.",
        )


    phishingAtt = AttackPattern(
        name = "Spearphishing Attachment, MITRE T1566.001",
        description = "In mid-2013, the actor used phishing emails containing executable file attachments with fake double extensions (filename.pdf.exe). After 2015, the actor moved on to less obvious files containing publicly available exploits, such as .doc, .pps, .docx, .rar, and password protected .rar files. These attempts involved legitimate lure documents in .pdf, .docx, and .mht formats to captivate the target’s attention while also executing malware",
    )

    phishingLink = AttackPattern(
        name = "Spearphishing Link, MITRE T1566.002",
        description = "In 2019 phishing campaigns, ModifiedElephant operators also took the approach of providing links to files hosted externally for manual download and execution by the target.",
    )

    phishingUsedByModifiedElephant = Relationship(
        plantingCampaigns,
        'uses',
        phishingAtt,
    )

    phishingLinkUsedByModifiedElephant = Relationship(
        plantingCampaigns,
        'uses',
        phishingLink,
    )

    bhima = Identity(
        name = "Bhima Koregaon Case",
        description = "activists, human rights defenders, journalists, academics, and law professionals in India are those most highly targeted. Notable targets include individuals associated with the Bhima Koregaon case.",
    )

    victimsAssociatedWithBhima = Relationship(
        victims,
        'related-to',
        bhima,
    )

    userExecMaliciousFile = AttackPattern(
        name = "User Execution: Malicious File, MITRE ATT&CK T1204.002",
        description = "Their primary delivery mechanism is malicious Microsoft Office document files weaponized to deliver the malware of choice at the time. The specific payloads changed over the years and across different targets. However, some notable trends remain.",
    )

    campaignUsesUserExecMaliciousFile = Relationship(
        plantingCampaigns,
        'uses',
        userExecMaliciousFile,
    )

    office = Infrastructure(
        name = "Microsoft Office",
        description = "Their primary delivery mechanism is malicious Microsoft Office document files weaponized to deliver the malware of choice at the time. ",
        )

    campaignConductedByModifiedElephant = Relationship(
        plantingCampaigns,
        'attributed-to',
        modifiedElephant,
    )

    campaignTargetsOffice = Relationship(
        userExecMaliciousFile,
        'uses',
        office,
    )

    phishingAttRelatedToUserExec = Relationship(
        phishingAtt,
        'related-to',
        userExecMaliciousFile,
    )

    phishingLinkRelatedToUserExec = Relationship(
        phishingLink,
        'related-to',
        userExecMaliciousFile,
    )

    vuln = Vulnerability(
        name = "Vulnerabilities",
        description = "Observed lure documents repeatedly made use of CVE-2012-0158, CVE-2014-1761, CVE-2013-3906, CVE-2015-1641 exploits to drop and execute their malware of choice",
    )

    campaingTargetsVuln = Relationship(
        plantingCampaigns,
        'targets',
        vuln,
    )

    sideWinder = ThreatActor(
        name = "SideWinder",
        description = "Notably, a separate Indian-nexus threat actor, SideWinder, is placed alongside ModifiedElephant in this graph as they were observed targeting the same individuals",
    )

    sideWinderTargetsVictims = Relationship(
        sideWinder,
        'targets',
        victims,
    )

    sideWinderLocatedinIndia = Relationship(
        sideWinder,
        'located-at',
        india,
    )

    netWire = Malware(
        name = "NetWire",
        description = "The primary malware families deployed were NetWire and DarkComet remote access trojans (RATs).",
        is_family = True,
    )

    darkComet = Malware(
        name = "DarkComet",
        description = "The primary malware families deployed were NetWire and DarkComet remote access trojans (RATs).",
        is_family = True,
    )

    ltrPDF = Indicator(
        name = "Ltr_1804_to_cc.pdf",
        description = "One particular activity revolves around the file Ltr_1804_to_cc.pdf, which contains details of an assassination plot against Prime Minister Modi. A forensic report by Arsenal Consulting showed that this file, one of the more incriminating pieces of evidence obtained by the police, was one of many files delivered via a NetWire RAT remote session that we associate with ModifiedElephant.",
        pattern = "[file:name = 'Ltr_1804_to_cc.pdf']",
        pattern_type = "stix",
    )

    fileIndicatesModifiedElephant = Relationship(
        ltrPDF,
        'indicates',
        netWire,
    )

    phishingDeliversNetWire = Relationship(
        userExecMaliciousFile,
        'delivers',
        netWire,
    )

    phishingDeliversDarkComet = Relationship(
        userExecMaliciousFile,
        'delivers',
        darkComet,
    )

    masquerading = AttackPattern(
        name = "Masquerading: Double File Extension, MITRE ATT&CK T1036.007",
        description = "n mid-2013, the actor used phishing emails containing executable file attachments with fake double extensions (filename.pdf.exe)",
    )

    campaignUsesMasquerading = Relationship(
        plantingCampaigns,
        'uses',
        masquerading,
    )

    userExecRelatedToPhishing = Relationship(
        userExecMaliciousFile,
        'related-to',
        phishingAtt,
    )

    userExecRelatedToPhishingLink = Relationship(
        userExecMaliciousFile,
        'related-to',
        phishingLink,
    )

    keyLogger = Malware(
        name = "KeyLoggers",
        description = "Known victims have also been targeted with keylogger payloads stretching as far back as 2012 (0a3d635eb11e78e6397a32c99dc0fd5a). These keyloggers, packed at delivery, are written in Visual Basic and are not the least bit technically impressive. Moreover, they’re built in such a brittle fashion that they no longer function.",
        is_family = True,
        implementation_languages = ["Visual Basic"],
    )

    meKeylogger = Malware(
        name = "ModifiedElephant Keylogger variant",
        description = "The overall structure of the keylogger is fairly similar to code openly shared on Italian hacking forums in 2012. The ModifiedElephant variant creates a hidden window titled ‘cssrs incubator ’ along with SetWindowsHookEx to monitor for keystrokes.",
        is_family = False,
    )

    phishingDeliversKeyLogger = Relationship(
        userExecMaliciousFile,
        'delivers',
        meKeylogger,
    )


    variantOriginatesFromKeyLogger = Relationship(
        meKeylogger,
        'variant-of',
        keyLogger,
    )

    variantAttributedToModifiedElephant = Relationship(
        meKeylogger,
        'attributed-to',
        modifiedElephant,
    )

    itHackingForum = Identity(
        name = "Italian hacking forum",
        description = "The overall structure of the keylogger is fairly similar to code openly shared on Italian hacking forums in 2012.",
    )

    variantOriginatesFromForum = Relationship(
        meKeylogger,
        'derived-from',
        itHackingForum,
    )

    outdatedEndpoint = Infrastructure(
        name = "Outdated whatismyip endpoint",
        description = "For example, the keylogger will use a GET request to an outdated ‘whatismyip. com’ endpoint in order to get the victim system’s IP",
    )

    meKeyloggerTargetsEndpoint = Relationship(
        meKeylogger,
        'uses',
        outdatedEndpoint,
    )

    microsoftSchemaSMTP = Infrastructure(
        name = "Microsoft Schema SMTP",
        description = "Similarly, in order to exfiltrate the logs, the keylogger pulls Microsoft schema templates to set up an SMTP server and push out the content using a hardcoded (but obfuscated) email address.",
    )

    meKeyloggerTargetsSMTP = Relationship(
        meKeylogger,
        'uses',
        microsoftSchemaSMTP,
    )

    hardcodedSMTPCredentials = Indicator(
        name = "Hardcoded SMTP credentials",
        description = "The keylogger makes use of hardcoded SMTP credentials and email addresses to deliver the logged keystrokes to attacker controlled accounts",
        pattern = "[email-message:from_ref.value = 'chiragdin3@gmail.com' OR email-message:from_ref.value = 'loggerdata123@gmail.com' OR email-message:from_ref.value = 'maalhamara@gmail.com' OR email-message:from_ref.value = 'nayaamaal1@yahoo.com' OR email-message:from_ref.value = 'maalhamara2@gmail.com' OR email-message:from_ref.value = 'nayaamaal122@yahoo.com' OR email-message:from_ref.value = 'nayaamaal2@yahoo.in' OR email-message:from_ref.value = 'nayaamaal4@yahoo.com' OR email-message:from_ref.value = 'newmaal@yahoo.com' OR email-message:from_ref.value = 'shab03@indiatimes.com' OR email-message:from_ref.value = 'tamizhviduthalai@gmail.com' OR email-message:from_ref.value = 'tryluck222@gmail.com' OR email-message:from_ref.value = 'volvoxyz123@gmail.com']",
        pattern_type = "stix",
    )

    credentialsIndicateKeylogger = Relationship(
        hardcodedSMTPCredentials,
        'indicates',
        meKeylogger,
    )

    samplesHash = Indicator(
        name = "Associated samples",
        description = "The keylogger makes use of hardcoded SMTP credentials and email addresses to deliver the logged keystrokes to attacker controlled accounts",
        pattern = "[file:hashes.MD5 = '0a3d635eb11e78e6397a32c99dc0fd5a' OR file:hashes.MD5 = 'c095d257983acca64eb52979cfc847ef' OR file:hashes.MD5 = '0a3d635eb11e78e6397a32c99dc0fd5a' OR file:hashes.MD5 = '56d573d4c811e69a992ab3088e44c268' OR file:hashes.MD5 = '1396f720bc7615385bc5df49bbd50d29' OR file:hashes.MD5 = 'd883399966cb29c7c6c358b7c9fdb951' OR file:hashes.MD5 = 'eff9b8e1ee17cd00702279db5de39a3c' OR file:hashes.MD5 = '0db49f572bb1634a4217b5215b1c2c6f' OR file:hashes.MD5 = 'ea324dd1dbc79fad591ca46ead4676a1' OR file:hashes.MD5 = 'fd4902b8a4a4718f5219b301475e81aa' OR file:hashes.MD5 = '0db49f572bb1634a4217b5215b1c2c6f' OR file:hashes.MD5 = 'd883399966cb29c7c6c358b7c9fdb951' OR file:hashes.MD5 = 'ea324dd1dbc79fad591ca46ead4676a1' OR file:hashes.MD5 = '1396f720bc7615385bc5df49bbd50d29' OR file:hashes.MD5 = 'fd4902b8a4a4718f5219b301475e81aa' OR file:hashes.MD5 = 'c095d257983acca64eb52979cfc847ef' OR file:hashes.MD5 = '1720ae54d8ca630b914f622dcf0c1878' OR file:hashes.MD5 = '56d573d4c811e69a992ab3088e44c268' OR file:hashes.MD5 = 'ef42dc2b27db73131e1c01ca9c9c41b6']",
        pattern_type = "stix",
    )

    samplesAssociatedToCredentials = Relationship(
        samplesHash,
        'related-to',
        hardcodedSMTPCredentials,
    )

    exfiltration = AttackPattern(
        name = "Exfiltration Over Alternative Protocol, MITRE ATT&CK T1048.002",
        description = "Similarly, in order to exfiltrate the logs, the keylogger pulls Microsoft schema templates to set up an SMTP server and push out the content using a hardcoded (but obfuscated) email address."
    )

    keyloggerUsesExfiltration = Relationship(
        meKeylogger,
        'uses',
        exfiltration,
    )

    hardcodedSMTPCredentialsIndicateExfiltration = Relationship(
        hardcodedSMTPCredentials,
        'indicates',
        exfiltration,
    )

    keylogging = AttackPattern(
        name = "Input Capture: Keylogging, MITRE ATT&CK T1056.001",
        description = "The keylogger makes use of hardcoded SMTP credentials and email addresses to deliver the logged keystrokes to attacker controlled accounts"
    )

    keyloggerUsesKeylogging = Relationship(
        meKeylogger,
        'uses',
        keylogging,
    )

    systemInfoDiscovery = AttackPattern(
        name = "System Information Discovery, MITRE ATT&CK T1082",
        description = "It registers the mutex “4oR_$$$tonelsu-mviiLempel-Ziv” and uses the VBScript to WMI connector to query for the victim system’s MAC address and operating system",
    )

    keyloggerUsesSystemInfoDiscovery = Relationship(
        meKeylogger,
        'uses',
        systemInfoDiscovery,
    )

    commodityTrojan = Malware(
        name = "Commodity Trojan",
        description = "ModifiedElephant also sent multiple phishing emails containing both NetWire and Android malware payloads at the same time. The Android malware is an unidentified commodity trojan delivered as an APK file (0330921c85d582deb2b77a4dc53c78b3).",
        is_family = True,
    )

    androidMalware = Malware(
        name = "Android Malware",
        description = "ModifiedElephant also sent multiple phishing emails containing both NetWire and Android malware payloads at the same time. The Android malware is an unidentified commodity trojan delivered as an APK file (0330921c85d582deb2b77a4dc53c78b3).",
        is_family = False,
    )

    phishingDeliversCommodityTrojan = Relationship(
        userExecMaliciousFile,
        'delivers',
        androidMalware,
    )

    androidMalwareisSubtypeOfCommodityTrojan = Relationship(
        androidMalware,
        'derived-from',
        commodityTrojan,
    )

    apkFile = Indicator(
        name = "APK file",
        description = "The Android malware is an unidentified commodity trojan delivered as an APK file (0330921c85d582deb2b77a4dc53c78b3).",
        pattern = "[file:hashes.MD5 = '0330921c85d582deb2b77a4dc53c78b3']",
        pattern_type = "stix",
    )

    apkFileAssociatedToAndroidMalware = Relationship(
        apkFile,
        'indicates',
        androidMalware,
    )

    androidMalwareDeliveredWithNetWire = Relationship(
        androidMalware,
        'related-to',
        netWire,
    )

    pegasus = Malware(
        name = "Pegasus",
        description = " Amnesty International identified NSO Group’s Pegasus being used in targeted attacks in 2019 against human rights defenders related to the Bhima Koregaon case.",
        is_family = False,
    )

    victimsTargetedByPegasus = Relationship(
        pegasus,
        'targets',
        victims,
    )

    nsoGroup = ThreatActor(
        name = "NSO Group",
        description = "Amnesty International identified NSO Group’s Pegasus being used in targeted attacks in 2019 against human rights defenders related to the Bhima Koregaon case.",
    )

    pegasusAttributedToNSO = Relationship(
        pegasus,
        'attributed-to',
        nsoGroup,
    )

    ronaWilson = Identity(
        name = "Rona Wilson",
        description = "Additionally, the Bhima Koregaon case defendant Rona Wilson’s iPhone was targeted with Pegasus since 2017 based on a digital forensics analysis of an iTunes backup found in the forensic disk images analyzed by Arsenal Consulting.",
    )

    pegasusTargetsRonaWilson = Relationship(
        pegasus,
        'targets',
        ronaWilson,
    )

    ronaAssociatedWithBhima = Relationship(
        ronaWilson,
        'related-to',
        bhima,
    )

    itunesBackup = Indicator(
        name = "iTunes backup",
        description = "Additionally, the Bhima Koregaon case defendant Rona Wilson’s iPhone was targeted with Pegasus since 2017 based on a digital forensics analysis of an iTunes backup found in the forensic disk images analyzed by Arsenal Consulting.",
        pattern = "[file:path MATCHES '.*\\\\Apple Computer\\\\MobileSync\\\\Backup\\\\.*']",
        pattern_type = "stix",
    )

    backupIndicatesPegasus = Relationship(
        itunesBackup,
        'indicates',
        pegasus,
    )

    phishingSideWinderCampaign = Campaign(
        name = "SideWinder Phishing Campaign",
        description = "Between February 2013 and January 2014 one target, Rona Wilson, received phishing emails that can be attributed to the SideWinder threat actor.",
    )

    sideWinderCampaignTargetsRona = Relationship(
        phishingSideWinderCampaign,
        'targets',
        ronaWilson,
    )

    campaignAttributedToSideWinder = Relationship(
        phishingSideWinderCampaign,
        'attributed-to',
        sideWinder,
    )

    emailPayloads = Indicator(
        name = "Email payloads",
        description = "These payloads were specifically labeled as indicators in the report.",
        pattern = "[file:hashes.MD5 = 'ca91cea6038ebc431c88d7a3280566f5' OR file:hashes.MD5 = '1720ae54d8ca630b914f622dcf0c1878' OR file:hashes.MD5 = '0a3d635eb11e78e6397a32c99dc0fd5a' OR file:hashes.MD5 = 'ebbddbdadfa5a7e3e5f00faf27543909' OR file:hashes.MD5 = '93f53bf0f3db53aebcad54a4aa8cc833' OR file:hashes.MD5 = '5c5279eab1cbffec7d174a79e4233217' OR file:hashes.MD5 = '7ad281f61b89a85ae69242f9bd1a28be' OR file:hashes.MD5 = 'cc634fe1d5087d629b141d242ff49732' OR file:hashes.MD5 = '7fa8bb8c90a1d1864a5eda90bb8fa2a3' OR file:hashes.MD5 = 'eef779774586e59a0e387f7ce06b092e' OR file:hashes.MD5 = 'b8a464741d16dcf046b1e27d63f62bcd' OR file:hashes.MD5 = 'e631b2f8496c40e54951a2daebfc73ae' OR file:hashes.MD5 = 'ad1b6380efb0aad16f01bd1a23f2e649' OR file:hashes.MD5 = '3e38ed7d2168d8170c50db86e5ebd99c' OR file:hashes.MD5 = 'ae95cf0cd0e1a5cd6561ae3a17968dec' OR file:hashes.MD5 = 'a650de5d94dd938d9fd0cf55fae83dd6' OR file:hashes.MD5 = 'c9da1fa9e874b68df14788c80ca5cfee' OR file:hashes.MD5 = '319444e7bd7a20caef38dfcf22948f3c']",
        pattern_type = "stix",
    )

    maliciousDomains = Indicator(
        name = "Malicious domains",
        description = "These domains were specifically labeled as indicators in the report.",
        pattern = "[domain-name:value IN ('pahiclisting.ddns.net', 'bzone.no-ip.biz', 'johnmarcus.zapto.org', 'ramesh212121.zapto.org', 'atlaswebportal.zapto.org', 'testingnew.no-ip.org', 'nepal3.msntv.org', 'socialstatistics.zapto.org', 'socialstudies.zapto.org', 'gayakwaad.com', 'knudandersen.zapto.org', 'jasonhistoryarticles.read-books.org', 'duniaenewsportal.ddns.net', 'vinaychutiya.no-ip.biz', 'researchplanet.zapto.org', 'greenpeacesite.com', 'new-agency.us', 'chivalkarstone.com', 'newmms.ru')]",
        pattern_type = "stix",
    )

    domainsIndicateLinkPhishing = Relationship(
        maliciousDomains,
        'indicates',
        phishingLink,
    )

    payloadsIndicateAttachmentPhishing = Relationship(
        emailPayloads,
        'indicates',
        phishingAtt,
    )

    payloadsIndicateUserExec = Relationship(
        emailPayloads,
        'indicates',
        userExecMaliciousFile,
    )

    domainsIndicateUserExec = Relationship(
        maliciousDomains,
        'indicates',
        userExecMaliciousFile,
    )

    operationHangover = Campaign(
        name = "Operation Hangover",
        description = "ModifiedElephant phishing email payloads (b822d8162dd540f29c0d8af28847246e) share infrastructure overlaps (new-agency[.]us) with Operation Hangover. Operation Hangover includes surveillance efforts against targets of interest to Indian national security, both foreign and domestic, in addition to industrial espionage efforts against organizations around the world.",
    )

    indianGovernment = Infrastructure(
        name = "Indian Government",
        description = "Operation Hangover includes surveillance efforts against targets of interest to Indian national security, both foreign and domestic, in addition to industrial espionage efforts against organizations around the world.",
    )

    operationHangoverAttributedToIndianGov = Relationship(
        operationHangover,
        'attributed-to',
        indianGovernment,
    )

    emailPayloadsAssociatedToOperationHangover = Relationship(
        emailPayloads,
        'related-to',
        operationHangover,
    )

    moosaAbdAliAli = Identity(
        name = "Moosa Abd-Ali Ali",
        description = "Another curious finding is the inclusion of the string “Logs from Moosa’s” found in a keylogger sample closely associated with ModifiedElephant activity in 2012 (c14e101c055c9cb549c75e90d0a99c0a). The string could be a reference to Moosa Abd-Ali Ali, the Bahrain activist targeted around the same time, with FinFisher spyware.",
    )

    emailPayloadsReferencingMoosa = Relationship(
        emailPayloads,
        'related-to',
        moosaAbdAliAli,
    )

    FinFisher = Malware(
        name = "FinFisher",
        description = "Another curious finding is the inclusion of the string “Logs from Moosa’s” found in a keylogger sample closely associated with ModifiedElephant activity in 2012 (c14e101c055c9cb549c75e90d0a99c0a). The string could be a reference to Moosa Abd-Ali Ali, the Bahrain activist targeted around the same time, with FinFisher spyware.",
        is_family = True,
    )

    finfishertargetsMoosa = Relationship(
        FinFisher,
        'targets',
        moosaAbdAliAli,
    )

    unknownIdentity = Identity(
        name = "Unknown",
        description = "Attributing an attacker like ModifiedElephant is an interesting challenge.",
    )

    unknownIdentityAttributedToModifiedElephant = Relationship(
        unknownIdentity,
        'attributed-to',
        modifiedElephant,
    )

    bundle = Bundle(objects=[modifiedElephant, victims, meTargetsVictims, india, victimsLocatedinIndia, modifiedElephantTargetsIndia, plantingCampaigns, phishingAtt, phishingLink, phishingUsedByModifiedElephant, phishingLinkUsedByModifiedElephant, bhima, victimsAssociatedWithBhima, userExecMaliciousFile, campaignUsesUserExecMaliciousFile, office, campaignConductedByModifiedElephant, campaignTargetsOffice, phishingAttRelatedToUserExec, phishingLinkRelatedToUserExec, vuln, campaingTargetsVuln, sideWinder, sideWinderTargetsVictims, sideWinderLocatedinIndia, netWire, darkComet, ltrPDF, fileIndicatesModifiedElephant, phishingDeliversNetWire, phishingDeliversDarkComet, masquerading, campaignUsesMasquerading, userExecRelatedToPhishing, userExecRelatedToPhishingLink, keyLogger, meKeylogger, phishingDeliversKeyLogger, variantOriginatesFromKeyLogger, variantAttributedToModifiedElephant, itHackingForum, variantOriginatesFromForum, outdatedEndpoint, meKeyloggerTargetsEndpoint, microsoftSchemaSMTP, meKeyloggerTargetsSMTP, hardcodedSMTPCredentials, credentialsIndicateKeylogger, samplesHash, samplesAssociatedToCredentials, exfiltration, keyloggerUsesExfiltration, hardcodedSMTPCredentialsIndicateExfiltration, keylogging, keyloggerUsesKeylogging, systemInfoDiscovery, keyloggerUsesSystemInfoDiscovery, commodityTrojan, androidMalware, phishingDeliversCommodityTrojan, androidMalwareisSubtypeOfCommodityTrojan, apkFile, apkFileAssociatedToAndroidMalware, androidMalwareDeliveredWithNetWire, pegasus, victimsTargetedByPegasus, nsoGroup, pegasusAttributedToNSO, ronaWilson, pegasusTargetsRonaWilson, ronaAssociatedWithBhima, itunesBackup, backupIndicatesPegasus, phishingSideWinderCampaign, sideWinderCampaignTargetsRona, campaignAttributedToSideWinder, emailPayloads, maliciousDomains, domainsIndicateLinkPhishing, payloadsIndicateAttachmentPhishing, payloadsIndicateUserExec, domainsIndicateUserExec, operationHangover, indianGovernment, operationHangoverAttributedToIndianGov, emailPayloadsAssociatedToOperationHangover, moosaAbdAliAli, emailPayloadsReferencingMoosa, FinFisher, finfishertargetsMoosa, unknownIdentity, unknownIdentityAttributedToModifiedElephant])
    
    with open("stix_modifiedelephant_DAVIDEEDOARDO_PELLEGRINO.json", "w") as f:
        f.write(bundle.serialize(pretty=True))