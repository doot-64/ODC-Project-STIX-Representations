from stix2.v21 import *
from datetime import datetime

if __name__ == '__main__':
    svr = ThreatActor(
        name = "SVR",
        description = "Russian Foreign Intelligence Service (SVR) cyber actors [...] are exploiting CVE-2023-42793 at a large scale, targeting servers hosting JetBrains TeamCity software since September 2023.",
        aliases = ["Advanced Persistent Threat 29", "APT 29", "the Dukes", "Cozy Bear", "NOBELIUM/Midnight Blizzard"],
        first_seen = datetime(2013, 1, 1),
        goals = ["espionage", "sabotage"],
        resource_level = "government",
        sophistication = "advanced",
    )

    russia = Location(
        name = "Russia",
        country = "Russia",
    )

    svrLocatedinRussia = Relationship(svr, 'located-at', russia)

    jetBrainsTeamCity = Infrastructure(
        name = "JetBrains TeamCity",
        description = "Software developers use TeamCity software to manage and automate software compilation, building, testing, and releasing.",
    )

    jetBrainsTeamCityVuln = Vulnerability(
        name = "CVE-2023-42793",
        description = "By choosing to exploit CVE-2023-42793, a software development program, the authoring agencies assess the SVR could benefit from access to victims, particularly by allowing the threat actors to compromise the networks of dozens of software developers.",
    )

    teamCityCampaign = Campaign(
        name = "TeamCity Campaign",
        description = "Russian Foreign Intelligence Service (SVR) cyber actors [...] are exploiting CVE-2023-42793 at a large scale, targeting servers hosting JetBrains TeamCity software since September 2023.",
        first_seen = datetime(2023, 9, 1),
    )

    campaignCompromises = Relationship(teamCityCampaign, 'compromises', jetBrainsTeamCity)

    campaignExploits = Relationship(teamCityCampaign, 'exploits', jetBrainsTeamCityVuln)

    campaignAttributedToSVR = Relationship(teamCityCampaign, 'attributed-to', svr)

    victims = Infrastructure(
        name = "Any exploitable organization",
        description = "Generally, the victim types do not fit into any sort of pattern or trend, aside from having an unpatched, Internet-reachable JetBrains TeamCity server, leading to the assessment that SVR’s exploitation of these victims’ networks was opportunistic in nature and not necessarily a targeted attack.",
    )

    campaignTargets = Relationship(teamCityCampaign, 'targets', victims)

    solarWinds = Infrastructure(
        name = "SolarWinds Orion",
        description = "Although the SVR used such access to compromise SolarWinds and its customers in 2020, [...]",
    )

    svrTargetsSolarWinds = Relationship(svr, 'targets', solarWinds)

    spearphishingCampaign = Campaign(
        name = "Spearphishing Campaign",
        description = "A decade ago, public reports about SVR cyber activity focused largely on the SVR’s spearphishing operations, targeting government agencies, think tanks and policy analysis organizations, educational institutions, and political organizations.",
    )

    spearphishingCampaignAttributedToSVR = Relationship(spearphishingCampaign, 'attributed-to', svr)

    spearphishingVictims = Infrastructure(
        name = "Government agencies, think tanks, policy analysis organizations, educational institutions, political organizations",
        description = "The SVR’s spearphishing operations have targeted government agencies, think tanks and policy analysis organizations, educational institutions, and political organizations.",
    )

    spearphishingCampaignTargets = Relationship(spearphishingCampaign, 'targets', spearphishingVictims)

    spearphishing = AttackPattern(
        name = "Spearphishing - MITRE T1566",
        description = "The SVR’s spearphishing operations have targeted government agencies, think tanks and policy analysis organizations, educational institutions, and political organizations.",
    )

    spearphishingCampaignUsesSpearphishing = Relationship(spearphishingCampaign, 'uses', spearphishing)

    spearphishingReport = Report(
        name = "GRIZZLY STEPPE – Russian Malicious Cyber Activity",
        description = "In December 2016, the U.S. Government published a Joint Analysis Report titled “GRIZZLY STEPPE – Russian Malicious Cyber Activity,” which describes the SVR’s compromise of a U.S. political party leading up to a presidential election.",
        published = datetime(2016, 12, 1),
        object_refs = [spearphishingCampaign.id, spearphishingVictims.id],
    )

    reportOnSpearphishingCampaign = Relationship(spearphishingReport, 'related-to', spearphishingCampaign)

    diplomaticOrbiterCampaign = Campaign(
        name = "Diplomatic Orbiter Campaign",
        description = "The SVR’s use of spear phishing operations are visible today in its ongoing Diplomatic Orbiter campaign, primarily targeting diplomatic agencies.",
    )

    diplomaticOrbiterCampaignAttributedToSVR = Relationship(diplomaticOrbiterCampaign, 'attributed-to', svr)

    diplomaticOrbUsesSpearphishing = Relationship(diplomaticOrbiterCampaign, 'uses', spearphishing)

    diplomaticOrbiterVictims = Infrastructure(
        name = "Diplomatic agencies",
        description = "The SVR’s use of spear phishing operations are visible today in its ongoing Diplomatic Orbiter campaign, primarily targeting diplomatic agencies.",
    )

    diplomaticOrbiterCampaignTargets = Relationship(diplomaticOrbiterCampaign, 'targets', diplomaticOrbiterVictims)

    wellMessCampaign = Campaign(
        name = "WellMess Campaign",
        description = "n July 2020, U.S., U.K., and Canadian Governments jointly published an advisory revealing the SVR’s exploitation of CVEs to gain initial access to networks, and its deployment of custom malware known as WellMess, WellMail, and Sorefang to target organizations involved in COVID-19 vaccine development.",
    )

    wellMessCampaignAttributedToSVR = Relationship(wellMessCampaign, 'attributed-to', svr)

    wellMess = Malware(
        name = "WellMess",
        description = "In July 2020, U.S., U.K., and Canadian Governments jointly published an advisory revealing the SVR’s exploitation of CVEs to gain initial access to networks, and its deployment of custom malware known as WellMess, WellMail, and Sorefang to target organizations involved in COVID-19 vaccine development.",
        is_family = False,
        first_seen = datetime(2020, 7, 1),
    )

    wellMail = Malware(
        name = "WellMail",
        description = "In July 2020, U.S., U.K., and Canadian Governments jointly published an advisory revealing the SVR’s exploitation of CVEs to gain initial access to networks, and its deployment of custom malware known as WellMess, WellMail, and Sorefang to target organizations involved in COVID-19 vaccine development.",
        is_family = False,
        first_seen = datetime(2020, 7, 1),
    )

    sorefang = Malware(
        name = "Sorefang",
        description = "In July 2020, U.S., U.K., and Canadian Governments jointly published an advisory revealing the SVR’s exploitation of CVEs to gain initial access to networks, and its deployment of custom malware known as WellMess, WellMail, and Sorefang to target organizations involved in COVID-19 vaccine development.",
        is_family = False,
        first_seen = datetime(2020, 7, 1),
    )

    wellMessCampaignUsesWellMess = Relationship(wellMessCampaign, 'uses', wellMess)

    wellMessCampaignUsesWellMail = Relationship(wellMessCampaign, 'uses', wellMail)

    wellMessCampaignUsesSorefang = Relationship(wellMessCampaign, 'uses', sorefang)

    wellmessVictims = Infrastructure(
        name = "Organizations involved in COVID-19 vaccine development",
        description = "In July 2020, U.S., U.K., and Canadian Governments jointly published an advisory revealing the SVR’s exploitation of CVEs to gain initial access to networks, and its deployment of custom malware known as WellMess, WellMail, and Sorefang to target organizations involved in COVID-19 vaccine development.",
    )

    wellMessCampaignTargets = Relationship(wellMessCampaign, 'targets', wellmessVictims)

    energyCompanies = Infrastructure(
        name = "Energy companies",
        description = "Although not listed in the 2020 advisory, the authoring agencies can now disclose that the SVR’s WellMess campaign also targeted energy companies.",
    )

    wellMessCampaignTargetsEnergyCompanies = Relationship(wellMessCampaign, 'targets', energyCompanies)

    gatherVictimNetworkInfo = AttackPattern(
        name = "Network Service Discovery - MITRE T1046",
        description = "The SVR performed network reconnaissance using a mix of built-in commands and additional tools, such as port scanner and PowerSploit, which it launched into memory [T1046]. ",
    )

    teamCityCampaignUsesGatherVictimNetworkInfo = Relationship(teamCityCampaign, 'uses', gatherVictimNetworkInfo)

    powerSploit = Tool(
        name = "PowerSploit",
        description = "The SVR performed network reconnaissance using a mix of built-in commands and additional tools, such as port scanner and PowerSploit, which it launched into memory [T1046]. ",
    )

    gatherVictimNetworkInfoUsesPowerSploit = Relationship(gatherVictimNetworkInfo, 'uses', powerSploit)

    systemOwnerUserDiscovery = AttackPattern(
        name = "System Owner/User Discovery - MITRE T1033",
        description = "Initial observations show the SVR used the following basic, built-in commands to perform host reconnaissance [T1033],[T1059.003],[T1592.002]: [...]",
    )

    teamCityCampaignUsesSystemOwnerUserDiscovery = Relationship(teamCityCampaign, 'uses', systemOwnerUserDiscovery)

    commandAndScriptingInterpreter = AttackPattern(
        name = "Command and Scripting Interpreter - MITRE T1059",
        description = "Initial observations show the SVR used the following basic, built-in commands to perform host reconnaissance [T1033],[T1059.003],[T1592.002]: [...]",
    )

    teamCityCampaignUsesCommandAndScriptingInterpreter = Relationship(teamCityCampaign, 'uses', commandAndScriptingInterpreter)

    exfiltrationOverC2Channel = AttackPattern(
        name = "Exfiltration Over Command and Control Channel - MITRE T1041",
        description = "Additionally, the authoring agencies have observed the SVR exfiltrating files [T1041] which may provide insight into the host system’s operating system",
    )

    teamCityCampaignUsesExfiltrationOverC2Channel = Relationship(teamCityCampaign, 'uses', exfiltrationOverC2Channel)

    exploitationForPrivilegeEscalation = AttackPattern(
        name = "Exploitation for Privilege Escalation - MITRE T1068",
        description = "SVR cyber actors exploit JetBrains TeamCity vulnerability to achieve escalated privileges. To avoid detection, the SVR cyber actors used a “Bring Your Own Vulnerable Driver” technique to disable EDR and AV defense mechanisms.",
    )

    teamCityCampaignUsesExploitationForPrivilegeEscalation = Relationship(teamCityCampaign, 'uses', exploitationForPrivilegeEscalation)

    impairDefenses = AttackPattern(
        name = "Impair Defenses - MITRE T1562",
        description = "To avoid detection, the SVR used a “Bring Your Own Vulnerable Driver” [T1068] technique to disable or outright kill endpoint detection and response (EDR) and antivirus (AV) software [T1562.001]",
    )

    teamCityCampaignUsesImpairDefenses = Relationship(teamCityCampaign, 'uses', impairDefenses)

    bootAutostartExecution = AttackPattern(
        name = "Boot or Logon Autostart Execution - MITRE T1547",
        description = "SVR cyber actors used C:\\Windows\\system32\\ntoskrnl.exe to configure automatic system boot settings to maintain persistence",
    )

    teamCityCampaignUsesBootAutostartExecution = Relationship(teamCityCampaign, 'uses', bootAutostartExecution)

    stealOrForgeKerberosTickets = AttackPattern(
        name = "Steal or Forge Kerberos Tickets - MITRE T1558",
        description = "To secure long-term access to the environment, the SVR used the Rubeus toolkit to craft Ticket Granting Tickets (TGTs) [T1558.001]",
    )

    teamCityCampaignUsesStealOrForgeKerberosTickets = Relationship(teamCityCampaign, 'uses', stealOrForgeKerberosTickets)

    rubeus = Tool(
        name = "Rubeus",
        description = "To secure long-term access to the environment, the SVR used the Rubeus toolkit to craft Ticket Granting Tickets (TGTs) [T1558.001]",
    )

    stealOrForgeKerberosTicketsUsesRubeus = Relationship(stealOrForgeKerberosTickets, 'uses', rubeus)

    oneDrive = Infrastructure(
        name = "OneDrive",
        description = "To avoid detection by network monitoring, the SVR devised a covert C2 channel that used Microsoft OneDrive and Dropbox cloud services. [...] OneDrive is used as a primary communication channel while Dropbox is treated as a backup channel [T1567].",
    )

    dropBox = Infrastructure(
        name = "Dropbox",
        description = "To avoid detection by network monitoring, the SVR devised a covert C2 channel that used Microsoft OneDrive and Dropbox cloud services. [...] OneDrive is used as a primary communication channel while Dropbox is treated as a backup channel [T1567].",
    )

    graphicalProton = Malware(
        name = "Graphical Proton",
        description = "GraphicalProton is a simplistic backdoor that uses OneDrive, Dropbox, and randomly generated BMPs [T1027.001] to exchange data with the SVR operator",
        is_family = True,
    )

    graphicalProtonUsesOneDrive = Relationship(graphicalProton, 'uses', oneDrive)

    graphicalProtonUsesDropBox = Relationship(graphicalProton, 'uses', dropBox)

    exfiltrationOverC2ChannelUsesGraphicalProton = Relationship(exfiltrationOverC2Channel, 'uses', graphicalProton)

    gpHTTPSVariant = Malware(
        name = "GraphicalProton HTTPS variant",
        description = "a variant of GraphicalProton backdoor recently introduced by the SVR that forgoes using cloud-based services as a C2 channel and instead relies on HTTP request.",
        is_family = False,
    )

    exfiltrationOverC2ChannelUsesGPHTTPSVariant = Relationship(exfiltrationOverC2Channel, 'uses', gpHTTPSVariant)

    variantIsDerivedFromGraphicalProton = Relationship(gpHTTPSVariant, 'derived-from', graphicalProton)

    wordpress = Infrastructure(
        name = "WordPress",
        description = "To legitimize the C2 channel, SVR used a re-registered expired domain set up with dummy WordPress website."
    )

    httpsVariantUsesWordPress = Relationship(gpHTTPSVariant, 'uses', wordpress)

    sharpChromium = Tool(
        name = "SharpChromium",
        description = "In a few specific cases, the SVR used the SharpChromium tool to obtain sensitive browser data such as session cookies, browsing history, or saved logins"
    )

    exfiltrationOverC2ChannelUsesSharpChromium = Relationship(exfiltrationOverC2Channel, 'uses', sharpChromium)

    DSinternals = Tool(
        name = "DSinternals",
        description = "SVR also used DSInternals open source tool to interact with Directory Services. DSInternals allows to obtain a sensitive Domain information."
    )

    exfiltrationOverC2ChannelUsesDSinternals = Relationship(exfiltrationOverC2Channel, 'uses', DSinternals)

    rsockstun = Tool(
        name = "Rsockstun",
        description = "In selected environments the SVR used an additional tool named, “rr.exe”—a modified open source reverse socks tunneler named Rsockstun—to establish a tunnel to the C2 infrastructure [T1572]"
    )

    rrexe = Malware(
        name = "rr.exe",
        description = "In selected environments the SVR used an additional tool named, “rr.exe”—a modified open source reverse socks tunneler named Rsockstun—to establish a tunnel to the C2 infrastructure [T1572]",
        is_family = False,
    )

    exfiltrationOverC2ChannelUsesRsockstun = Relationship(exfiltrationOverC2Channel, 'uses', rrexe)

    rrexederivedFromRsockstun = Relationship(rrexe, 'derived-from', rsockstun)

    rrInfrastructure = Infrastructure(
        name = "C2 infrastructure",
        description = "The authoring agencies are aware of the following infrastructure used in conjunction with “rr.exe”: 65.20.97[.]203:443, Poetpages[.]com:8443"
    )

    c2url = URL(
        value = "https://Poetpages.com:8443"
    )

    c2ip = IPv4Address(
        value = "65.20.97.203:443"
    )

    rrInfrastructureHasURL = Relationship(rrInfrastructure, 'consists-of', c2url)

    rrInfrastructureHasIP = Relationship(rrInfrastructure, 'consists-of', c2ip)

    rrexeUsesC2Infrastructure = Relationship(rrexe, 'uses', rrInfrastructure)

    edrSandBlast = Tool(
        name = "EDRSandBlast",
        description = "This was done using an open source project called “EDRSandBlast.” The authoring agencies have observed the SVR using EDRSandBlast to remove protected process light (PPL) protection, which is used for controlling and protecting running processes and protecting them from infection. "
    )

    impairDefensesUsesEDRSandBlast = Relationship(impairDefenses, 'uses', edrSandBlast)

    mimikatz = Tool(
        name = "Mimikatz",
        description = "To facilitate privilege escalation [T1098], the SVR used multiple techniques, including WinPEAS, NoLMHash registry key modification, and the Mimikatz tool."
    )

    exploitationForPrivilegeEscalationUsesMimikatz = Relationship(exploitationForPrivilegeEscalation, 'uses', mimikatz)

    vcperf = Tool(
        name = "VCPerf",
        description = "In several cases SVR attempted to hide their backdoors via: [...] backdooring an open source application developed by Microsoft named vcperf. SVR modified and copied publicly available source code. After execution, backdoored vcperf dropped several DLLs to disc, one of those being a GraphicalProton backdoor"
    )

    moddedVCPerf = Malware(
        name = "Modded VCPerf",
        description = "In several cases SVR attempted to hide their backdoors via: [...] backdooring an open source application developed by Microsoft named vcperf. SVR modified and copied publicly available source code. After execution, backdoored vcperf dropped several DLLs to disc, one of those being a GraphicalProton backdoor",
        is_family = False,
    )

    moddedvcperfDerivedFromVCPerf = Relationship(moddedVCPerf, 'derived-from', vcperf)

    exploitationForPrivilegeEscalationUsesModdedVCPerf = Relationship(exploitationForPrivilegeEscalation, 'uses', moddedVCPerf)

    moddedVCPerfUsesGraphicalProton = Relationship(moddedVCPerf, 'drops', graphicalProton)

    zabbixVuln = Vulnerability(
        name = "Zabbix vulnerability",
        description = "In several cases SVR attempted to hide their backdoors via: [...] Abusing a DLL hijacking vulnerability in Zabbix software by replacing a legitimate Zabbix DLL with their one containing GraphicalProton backdoor",
    )

    exploitationForPrivilegeEscalationUsesZabbixVuln = Relationship(exploitationForPrivilegeEscalation, 'exploits', zabbixVuln)

    webrootVuln = Vulnerability(
        name = "Webroot vulnerability",
        description = "In several cases SVR attempted to hide their backdoors via: [...] Abusing a DLL hijacking vulnerability in Webroot antivirus software by replacing a legitimate Webroot DLL with their one containing GraphicalProton backdoor",
    )

    exploitationForPrivilegeEscalationUsesWebrootVuln = Relationship(exploitationForPrivilegeEscalation, 'exploits', webrootVuln)

    networkIOC = Indicator(
        name = "Network Indicators of Compromise",
        description = "The authoring agencies have observed the SVR using the following network indicators of compromise (IOCs):",
        pattern_type = "stix",
        pattern = "[ipv4-addr:value = '65.20.97.203' OR ipv4-addr:value = '65.21.51.58' OR ipv4-addr:value = '103.76.128.34']"
    )

    networkIOCIndicatesTeamCityCampaign = Relationship(networkIOC, 'indicates', teamCityCampaign)

    rrInfrastructurerelatedtoNetworkIOC = Relationship(rrInfrastructure, 'related-to', networkIOC)

    rrhash = Indicator(
        name = "rr.exe hash",
        description = "The authoring agencies have observed the SVR using the following hash indicators of compromise (IOCs):",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = 'CB83E5CB264161C28DE76A44D0EDB450745E773D24BEC5869D85F69633E44DCF']"
    )

    rrhashIndicatesRREXE = Relationship(rrhash, 'indicates', rrexe)

    graphicalProtonHash = Indicator(
        name = "GraphicalProton hashes",
        description = "The authoring agencies have observed the SVR using the following hash indicators of compromise (IOCs):",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = '01B5F7094DE0B2C6F8E28AA9A2DED678C166D615530E595621E692A9C0240732' OR file:hashes.'SHA-256' = '34C8F155601A3948DDB0D60B582CFE87DE970D443CC0E05DF48B1A1AD2E42B5E' OR file:hashes.'SHA-256' = '620D2BF14FE345EEF618FDD1DAC242B3A0BB65CCB75699FE00F7C671F2C1D869' OR file:hashes.'SHA-256' = '773F0102720AF2957859D6930CD09693824D87DB705B3303CEF9EE794375CE13' OR file:hashes.'SHA-256' = '7B666B978DBBE7C032CEF19A90993E8E4922B743EE839632BFA6D99314EA6C53' OR file:hashes.'SHA-256' = '8AFB71B7CE511B0BCE642F46D6FC5DD79FAD86A58223061B684313966EFEF9C7' OR file:hashes.'SHA-256' = '971F0CED6C42DD2B6E3EA3E6C54D0081CF9B06E79A38C2EDE3A2C5228C27A6DC' OR file:hashes.'SHA-256' = 'CB83E5CB264161C28DE76A44D0EDB450745E773D24BEC5869D85F69633E44DCF' OR file:hashes.'SHA-256' = 'CD3584D61C2724F927553770924149BB51811742A461146B15B34A26C92CAD43' OR file:hashes.'SHA-256' = 'EBE231C90FAD02590FC56D5840ACC63B90312B0E2FEE7DA3C7606027ED92600E' OR file:hashes.'SHA-256' = 'F1B40E6E5A7CBC22F7A0BD34607B13E7E3493B8AAD7431C47F1366F0256E23EB' OR file:hashes.'SHA-256' = 'C7B01242D2E15C3DA0F45B8ADEC4E6913E534849CDE16A2A6C480045E03FBEE4' OR file:hashes.'SHA-256' = '4BF1915785D7C6E0987EB9C15857F7AC67DC365177A1707B14822131D43A6166']"
    )

    graphicalProtonHashIndicatesGraphicalProton = Relationship(graphicalProtonHash, 'indicates', graphicalProton)

    gpHTTPSVariantHash = Indicator(
        name = "GraphicalProton HTTPS variant hashes",
        description = "The authoring agencies have observed the SVR using the following hash indicators of compromise (IOCs):",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = '18101518EAE3EEC6EBE453DE4C4C380160774D7C3ED5C79E1813013AC1BB0B93' OR file:hashes.'SHA-256' = '19F1EF66E449CF2A2B0283DBB756850CCA396114286E1485E35E6C672C9C3641' OR file:hashes.'SHA-256' = '1E74CF0223D57FD846E171F4A58790280D4593DF1F23132044076560A5455FF8' OR file:hashes.'SHA-256' = '219FB90D2E88A2197A9E08B0E7811E2E0BD23D59233287587CCC4642C2CF3D67' OR file:hashes.'SHA-256' = '92C7693E82A90D08249EDEAFBCA6533FED81B62E9E056DEC34C24756E0A130A6' OR file:hashes.'SHA-256' = 'B53E27C79EED8531B1E05827ACE2362603FB9F77F53CEE2E34940D570217CBF7' OR file:hashes.'SHA-256' = 'C37C109171F32456BBE57B8676CC533091E387E6BA733FBAA01175C43CFB6EBD' OR file:hashes.'SHA-256' = 'C40A8006A7B1F10B1B42FDD8D6D0F434BE503FB3400FB948AC9AB8DDFA5B78A0' OR file:hashes.'SHA-256' = 'C832462C15C8041191F190F7A88D25089D57F78E97161C3003D68D0CC2C4BAA3' OR file:hashes.'SHA-256' = 'F6194121E1540C3553273709127DFA1DAAB96B0ACFAB6E92548BFB4059913C69']"
    )

    gpHTTPSVariantHashIndicatesGPHTTPSVariant = Relationship(gpHTTPSVariantHash, 'indicates', gpHTTPSVariant)

    gphttpsurl = Indicator(
        name = "GraphicalProton HTTPS variant URL",
        pattern_type = "stix",
        pattern = "[url:value = 'hxxps://matclick.com/wp-query.php']"
    )

    gphttpsurlIndicatesGPHTTPSVariant = Relationship(gphttpsurl, 'indicates', gpHTTPSVariant)

    moddedVCPerfHash = Indicator(
        name = "Modded VCPerf hash",
        description = "The authoring agencies have observed the following hash indicators of compromise (IOCs):",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = 'D724728344FCF3812A0664A80270F7B4980B82342449A8C5A2FA510E10600443']"
    )

    moddedVCPerfHashIndicatesModdedVCPerf = Relationship(moddedVCPerfHash, 'indicates', moddedVCPerf)

    zabbixVulnHash = Indicator(
        name = "Backdoored Zabbix hash",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = '4EE70128C70D646C5C2A9A17AD05949CB1FBF1043E9D671998812B2DCE75CF0F']"
    )

    zabbixhasindicatesexploitationForPrivilegeEscalation = Relationship(zabbixVulnHash, 'indicates', exploitationForPrivilegeEscalation)

    webrootVulnHash = Indicator(
        name = "Backdoored Webroot hash",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = '950ADBAF66AB214DE837E6F1C00921C501746616A882EA8C42F1BAD5F9B6EFF4']"
    )

    webrootVulnHashIndicatesExploitationForPrivilegeEscalation = Relationship(webrootVulnHash, 'indicates', exploitationForPrivilegeEscalation)

    logMessageIndicator = Indicator(
         name = "Log message indicator",
         description = "On a Windows system, the log file C:\\TeamCity\\logs\\teamcity-server.log will contain a log message when an attacker modified the internal.properties file. There will also be a log message for every process created via the /app/rest/debug/processes endpoint.",
         pattern_type = "stix",
         pattern = "[file:name = 'internal.properties' AND file:parent_directory_ref.path = 'C:\\\\ProgramData\\\\JetBrains\\\\TeamCity\\\\config' AND file:x_custom_property = 'File edited by user with id=1']"
    )

    logMessageIndicatorIndicatesTeamCityCampaign = Relationship(logMessageIndicator, 'indicates', teamCityCampaign)

    sigmaRule1 = Indicator(
        name = "Sigma rule 1",
        description = "Detects whoami.exe execution and listing of privileges.",
        pattern_type = "sigma",
        pattern = "Image|endswith: 'whoami.exe' AND CommandLine|contains: ['priv', 'PRIV']",
    )

    sigmaRule2 = Indicator(
        name = "Sigma rule 2",
        description = "Detects nltest.exe execution and DC listing.",
        pattern_type = "sigma",
        pattern = "Image|endswith: 'nltest.exe' AND CommandLine|re: '.*dclist\:.*|.*DCLIST\:.*|.*dsgetdc\:.*|.*DSGETDC\:.*'",
    )

    sigmaRule3 = Indicator(
        name = "Sigma rule 3",
        description = "Detects DLL execution via WMI.",
        pattern_type = "sigma",
        pattern = "Image|endswith: 'WMIC.exe' AND CommandLine|contains|all: ['call', 'rundll32']",
    )

    sigmaRule4 = Indicator(
        name = "Sigma rule 4",
        description = "Detects processes with 'connect' and 'pass' as arguments indicating potentially malicious activity.",
        pattern_type = "sigma",
        pattern = "CommandLine|contains|all: ['pass', 'connect']",
    )

    sigmaRule10 = Indicator(
        name = "Sigma rule 10",
        description = "Detects PowerShell scripts enumerating services or drives, potential information gathering activity.",
        pattern_type = "sigma",
        pattern = "ScriptBlockText|contains|all: ['Get-WmiObject', '-Class', 'Win32_Service'] OR ScriptBlockText|contains|all: ['Get-WindowsDriver', '-Online', '-All']",
    )

    sigmaRule5 = Indicator(
        name = "Sigma rule 5",
        description = "Detects compression of files from temporary directories, possibly in preparation for data exfiltration.",
        pattern_type = "sigma",
        pattern = "ScriptBlockText|re: '.*Compress\\-Archive.*Path.*Windows\\\\[Tt]{1}emp\\\\[1-9]{1}.*DestinationPath.*Windows\\\\[Tt]{1}emp\\\\.*'",
    )

    sigmaRule6 = Indicator(
        name = "Sigma rule 6",
        description = "Detects loading of DLLs with specific names known to be associated with the GraphicalProton backdoor.",
        pattern_type = "sigma",
        pattern = "ImageLoaded|endswith: ['AclNumsInvertHost.dll', 'ModeBitmapNumericAnimate.dll', 'UnregisterAncestorAppendAuto.dll', 'DeregisterSeekUsers.dll', 'ScrollbarHandleGet.dll', 'PerformanceCaptionApi.dll', 'WowIcmpRemoveReg.dll', 'BlendMonitorStringBuild.dll', 'HandleFrequencyAll.dll', 'HardSwapColor.dll', 'LengthInMemoryActivate.dll', 'ParametersNamesPopup.dll', 'ModeFolderSignMove.dll', 'ChildPaletteConnected.dll', 'AddressResourcesSpec.dll']",
    )

    sigmaRule7 = Indicator(
        name = "Sigma rule 7",
        description = "Detects the use of 'reg.exe' to save sensitive registry entries, possibly for exfiltration or backup before making malicious modifications.",
        pattern_type = "sigma",
        pattern = "Image|endswith: 'reg.exe' AND CommandLine|contains: 'save' AND CommandLine|re: '.*HKLM\\\\SYSTEM.*|.*HKLM\\\\SECURITY.*|.*HKLM\\\\SAM.*'",
    )

    sigmaRule8 = Indicator(
        name = "Sigma rule 8",
        description = "Detects creation or manipulation of scheduled tasks with names associated with the GraphicalProton backdoor.",
        pattern_type = "sigma",
        pattern = "EventID: ['4698', '4699', '4702'] AND TaskName|contains: ['\\\\Microsoft\\\\Windows\\\\IISUpdateService', '\\\\Microsoft\\\\Windows\\\\WindowsDefenderService', '\\\\Microsoft\\\\Windows\\\\WindowsDefenderService2', '\\\\Microsoft\\\\DefenderService', '\\\\Microsoft\\\\Windows\\\\DefenderUPDService', '\\\\Microsoft\\\\Windows\\\\WiMSDFS', '\\\\Microsoft\\\\Windows\\\\Application Experience\\\\StartupAppTaskCkeck', '\\\\Microsoft\\\\Windows\\\\Windows Error Reporting\\\\SubmitReporting', '\\\\Microsoft\\\\Windows\\\\Windows Defender\\\\Defender Update Service', '\\\\WindowUpdate', '\\\\Microsoft\\\\Windows\\\\Windows Error Reporting\\\\CheckReporting', '\\\\Microsoft\\\\Windows\\\\Application Experience\\\\StartupAppTaskCheck', '\\\\Microsoft\\\\Windows\\\\Speech\\\\SpeechModelInstallTask', '\\\\Microsoft\\\\Windows\\\\Windows Filtering Platform\\\\BfeOnServiceStart', '\\\\Microsoft\\\\Windows\\\\Data Integrity Scan\\\\Data Integrity Update', '\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\Scheduled AutoCheck', '\\\\Microsoft\\\\Windows\\\\ATPUpd', '\\\\Microsoft\\\\Windows\\\\Windows Defender\\\\Service Update', '\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\Scheduled Check', '\\\\Microsoft\\\\Windows\\\\WindowsUpdate\\\\Scheduled AutoCheck', '\\\\Defender', '\\\\defender']",
    )

    sigmaRule9 = Indicator(
        name = "Sigma rule 9",
        description = "Detects modifications to specific sensitive registry keys, indicating potential security policy bypass attempts.",
        pattern_type = "sigma",
        pattern = "[registry:key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\DisableRestrictedAdmin' OR registry:key = 'HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash']",
    )

    sigmaRule11 = Indicator(
        name = "Sigma rule 11",
        description = "Detects the loading of drivers by their names or hashes known to be malicious or used in unauthorized modifications.",
        pattern_type = "sigma",
        pattern = "ImageLoaded|endswith: ['RTCore64.sys', 'DBUtils_2_3.sys'] OR Hashes|contains: ['01aa278b07b58dc46c84bd0b1b5c8e9ee4e62ea0bf7a695862444af32e87f1fd', '0296e2ce999e67c76352613a718e11516fe1b0efc3ffdb8918fc999dd76a73a5']",
    )

    sigmarule1indicatesTeamCityCampaign = Relationship(sigmaRule1, 'indicates', teamCityCampaign)

    sigmarule2indicatesTeamCityCampaign = Relationship(sigmaRule2, 'indicates', teamCityCampaign)

    sigmarule3indicatesTeamCityCampaign = Relationship(sigmaRule3, 'indicates', teamCityCampaign)

    sigmarule4indicatesTeamCityCampaign = Relationship(sigmaRule4, 'indicates', teamCityCampaign)

    sigmarule5indicatesTeamCityCampaign = Relationship(sigmaRule5, 'indicates', teamCityCampaign)

    sigmarule6indicatesTeamCityCampaign = Relationship(sigmaRule6, 'indicates', teamCityCampaign)

    sigmarule7indicatesTeamCityCampaign = Relationship(sigmaRule7, 'indicates', teamCityCampaign)

    sigmarule8indicatesTeamCityCampaign = Relationship(sigmaRule8, 'indicates', teamCityCampaign)

    sigmarule9indicatesTeamCityCampaign = Relationship(sigmaRule9, 'indicates', teamCityCampaign)

    sigmarule10indicatesTeamCityCampaign = Relationship(sigmaRule10, 'indicates', teamCityCampaign)

    sigmarule11indicatesTeamCityCampaign = Relationship(sigmaRule11, 'indicates', teamCityCampaign)

    yaraRule = Indicator(
        name = "YARA rule",
        description = "The following rule detects most known GraphicalProton variants: [...]",
        pattern_type = "yara",
        pattern = "rule APT29_GraphicalProton { strings: $op_string_crypt = { c1 e? (1b | 18 | 10 | 13 | 19 | 10) 48 [4] 8b [2] c1 e? (05 | 08 | 10 | 0d | 07) 09 ?? 48 } $op_decrypt_config = { 48 05 20 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4] 48 05 40 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4] 48 05 60 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4] 48 05 80 00 00 00 48 89 C1 48 [6] 41 B8 ?? ?? 00 00 E8 [4] 48 [4] 48 05 A0 00 00 00 } condition: all of them }",
    )

    yaraRuleIndicatesGraphicalProton = Relationship(yaraRule, 'indicates', graphicalProton)

    bundle = Bundle(objects=[svr, russia, svrLocatedinRussia, jetBrainsTeamCity, jetBrainsTeamCityVuln, teamCityCampaign, campaignCompromises, campaignExploits, campaignAttributedToSVR, victims, campaignTargets, solarWinds, svrTargetsSolarWinds, spearphishingCampaign, spearphishingCampaignAttributedToSVR, spearphishingVictims, spearphishingCampaignTargets, spearphishing, spearphishingCampaignUsesSpearphishing, reportOnSpearphishingCampaign, diplomaticOrbiterCampaign,
                              diplomaticOrbiterCampaignAttributedToSVR, diplomaticOrbUsesSpearphishing, diplomaticOrbiterVictims, diplomaticOrbiterCampaignTargets, wellMessCampaign, wellMessCampaignAttributedToSVR, wellMess, wellMail, sorefang, wellMessCampaignUsesWellMess, wellMessCampaignUsesWellMail, wellMessCampaignUsesSorefang, wellmessVictims, wellMessCampaignTargets, energyCompanies, wellMessCampaignTargetsEnergyCompanies, gatherVictimNetworkInfo, teamCityCampaignUsesGatherVictimNetworkInfo, powerSploit, gatherVictimNetworkInfoUsesPowerSploit, systemOwnerUserDiscovery, teamCityCampaignUsesSystemOwnerUserDiscovery, commandAndScriptingInterpreter, teamCityCampaignUsesCommandAndScriptingInterpreter, exfiltrationOverC2Channel, teamCityCampaignUsesExfiltrationOverC2Channel, exploitationForPrivilegeEscalation, teamCityCampaignUsesExploitationForPrivilegeEscalation, impairDefenses, teamCityCampaignUsesImpairDefenses, bootAutostartExecution, teamCityCampaignUsesBootAutostartExecution, stealOrForgeKerberosTickets, teamCityCampaignUsesStealOrForgeKerberosTickets, rubeus, stealOrForgeKerberosTicketsUsesRubeus, oneDrive, dropBox, graphicalProton, graphicalProtonUsesOneDrive, graphicalProtonUsesDropBox, exfiltrationOverC2ChannelUsesGraphicalProton, gpHTTPSVariant, exfiltrationOverC2ChannelUsesGPHTTPSVariant, variantIsDerivedFromGraphicalProton, wordpress, sharpChromium, exfiltrationOverC2ChannelUsesSharpChromium, DSinternals, httpsVariantUsesWordPress, exfiltrationOverC2ChannelUsesDSinternals, rsockstun, rrexe, exfiltrationOverC2ChannelUsesRsockstun, rrexederivedFromRsockstun, rrInfrastructure, c2url, c2ip, rrInfrastructureHasURL, rrInfrastructureHasIP, rrexeUsesC2Infrastructure, edrSandBlast, impairDefensesUsesEDRSandBlast, mimikatz, exploitationForPrivilegeEscalationUsesMimikatz, vcperf, moddedVCPerf, moddedvcperfDerivedFromVCPerf, exploitationForPrivilegeEscalationUsesModdedVCPerf, moddedVCPerfUsesGraphicalProton, zabbixVuln, exploitationForPrivilegeEscalationUsesZabbixVuln, webrootVuln, exploitationForPrivilegeEscalationUsesWebrootVuln, networkIOC, networkIOCIndicatesTeamCityCampaign, rrInfrastructurerelatedtoNetworkIOC, rrhash, rrhashIndicatesRREXE, graphicalProtonHash, graphicalProtonHashIndicatesGraphicalProton, gpHTTPSVariantHash, gpHTTPSVariantHashIndicatesGPHTTPSVariant, gphttpsurl, gphttpsurlIndicatesGPHTTPSVariant, moddedVCPerfHash, moddedVCPerfHashIndicatesModdedVCPerf, zabbixVulnHash, zabbixhasindicatesexploitationForPrivilegeEscalation, webrootVulnHash, webrootVulnHashIndicatesExploitationForPrivilegeEscalation, logMessageIndicator, logMessageIndicatorIndicatesTeamCityCampaign, sigmaRule1, sigmaRule2, sigmaRule3, sigmaRule4, sigmaRule10, sigmaRule5, sigmaRule6, sigmaRule7, sigmaRule8, sigmaRule9, sigmaRule11, sigmarule1indicatesTeamCityCampaign, sigmarule2indicatesTeamCityCampaign, sigmarule3indicatesTeamCityCampaign, sigmarule4indicatesTeamCityCampaign, sigmarule5indicatesTeamCityCampaign, sigmarule6indicatesTeamCityCampaign, sigmarule7indicatesTeamCityCampaign, sigmarule8indicatesTeamCityCampaign, sigmarule9indicatesTeamCityCampaign, sigmarule10indicatesTeamCityCampaign, sigmarule11indicatesTeamCityCampaign, yaraRule, yaraRuleIndicatesGraphicalProton])

    with open("stix_cisa_DAVIDEEDOARDO_PELLEGRINO.json", "w") as f:
        f.write(bundle.serialize(pretty=True))
