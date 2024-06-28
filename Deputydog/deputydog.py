from stix2.v21 import *
from datetime import datetime

if __name__ == '__main__':
    campaign = Campaign(
        name="Operation DeputyDog",
        description="FireEye has discovered a campaign leveraging the recently announced zero-day CVE-2013-3893. This campaign, which we have labeled ‘Operation DeputyDog’, began as early as August 19, 2013 and appears to have targeted organizations in Japan.",
        first_seen=datetime(year=2013, month=8, day=19),
    )

    unknownGroup = ThreatActor(
        name="Unknown Threat Actor",
        description="The group responsible for this new operation is the same threat actor that compromised Bit9 in February 2013.",
    )

    unknownIdentity = Identity(
        name="Unknown Identity",
        description="The group responsible for this new operation is the same threat actor that compromised Bit9 in February 2013.",
    )

    identityOfGroup = Relationship(
        unknownGroup,
        'attributed-to',
        unknownIdentity,
    )

    campaignAttributedto = Relationship(
        campaign,
        'attributed-to',
        unknownGroup,
    )

    cveVuln = Vulnerability(
        name="CVE-2013-3893",
        description="On September 17, 2013 Microsoft published details regarding a new zero-day exploit in Internet Explorer that was being used in targeted attacks.",
    )

    campaignTargetsVuln = Relationship(
        campaign,
        'targets',
        cveVuln,
    )

    internetExplorer = Infrastructure(
        name="Internet Explorer",
        description="On September 17, 2013 Microsoft published details regarding a new zero-day exploit in Internet Explorer that was being used in targeted attacks.",
    )

    campaignTargetsInternetExplorer = Relationship(
        campaign,
        'targets',
        internetExplorer,
    )

    unknownJapaneseOrg = Infrastructure(
        name="Unknown Japanese Organization",
        description="FireEye can confirm reports that these attacks were directed against entities in Japan.",
    )

    campaignTargetsOrg = Relationship(
        campaign,
        'targets',
        unknownJapaneseOrg,
    )

    japan = Location(
        name="Japan",
        country= "Japan",
        description="FireEye can confirm reports that these attacks were directed against entities in Japan.",
    )

    orgLocatedInJapan = Relationship(
        unknownJapaneseOrg,
        'located-at',
        japan,
    )

    campaignOnBit9 = Campaign(
        name="Campaign on Bit9",
        description="According to Bit9, the attackers that penetrated their network dropped two variants of the HiKit rootkit.",
    )

    attributionOfCampaign = Relationship(
        campaignOnBit9,
        'attributed-to',
        unknownGroup,
    )

    img = Malware(
        name="img20130823.jpg",
        description= "The payload was hosted on a server in Hong Kong (210.176.3.130) and was named 'img20130823.jpg'",
        is_family = False,
        aliases = ["8aba4b5184072f2a50cbc5ecfe326701"],
    )


    imgRelatedToCampaign = Relationship(
        campaign,
        'uses',
        img,
    )

    hkServer = Infrastructure(
        name="Hong Kong Server",
        aliases=["210.176.3.130"],
        description= "The payload was hosted on a server in Hong Kong (210.176.3.130) and was named 'img20130823.jpg'",
    )

    hkServerIP = IPv4Address(
        value="210.176.3.130",
    )

    hkServerconsistsOfIP = Relationship(
        hkServer,
        'consists-of',
        hkServerIP,
    )

    imgLocatedAtHKServer = Relationship(
        hkServer,
        'delivers',
        img,
    )

    hk = Location(
        name="Hong Kong",
        country="Hong Kong",
        description="The payload was hosted on a server in Hong Kong",
    )

    hkServerLocatedInHK = Relationship(
        hkServer,
        'located-at',
        hk,
    )

    dll = Indicator(
        name="28542CC0.dll",
        pattern = "[file:hashes.'MD5' = '46fd936bada07819f61ec3790cb08e19']",
        pattern_type = "stix",
        description="Upon execution, 8aba4b5184072f2a50cbc5ecfe326701 writes “28542CC0.dll” (MD5:46fd936bada07819f61ec3790cb08e19)",
    )

    dlldroppedByImg = Relationship(
        img,
        'drops',
        dll,
    )

    persistenceByRegistry = AttackPattern(
        name="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder, MITRE ATT&CK T1547.001",
        description="In order to maintain persistence, the original malware adds this registry key: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\28542CC0",
    )

    persistenceUsedByImg = Relationship(
        img,
        'uses',
        persistenceByRegistry,
    )

    masquerading = AttackPattern(
        name = "Masquerading: Masquerade File Type, MITRE ATT&CK T1036.008",
        description = "he payload was hosted on a server in Hong Kong (210.176.3.130) and was named “img20130823.jpg”. Although it had a .jpg file extension, it was not an image file. The file, when XORed with 0×95, was an executable (MD5: 8aba4b5184072f2a50cbc5ecfe326701).",
    )

    masqueradingUsedByImg = Relationship(
        img,
        'uses',
        masquerading,
    )

    c2WebProtocols = AttackPattern(
        name = "Command and Control, Application Layer Protocol: Web Protocols, MITRE ATT&CK T1071.001",
        description = "The unique HTTP header “Agtid:” contains 8 characters followed by “08x”. The same pattern can be seen in the POST content as well",
    )

    c2WebProtocolsUsedByImg = Relationship(
        img,
        'uses',
        c2WebProtocols,
    )

    CCserverInSK = Infrastructure(
        name="CC Server in South Korea",
        aliases=["180.150.228.102"],
        description="The malware (8aba4b5184072f2a50cbc5ecfe326701) then connects to a host in South Korea (180.150.228.102).",
    )

    CCserverIP = IPv4Address(
        value="80.150.228.102"
    )

    CCserverconsistsOfIP = Relationship(
        CCserverInSK,
        'consists-of',
        CCserverIP,
    )

    sk = Location(
        name="South Korea",
        country="South Korea",
    )

    serverInSKLocatedInSK = Relationship(
        CCserverInSK,
        'located-at',
        sk,
    )

    imgConnectsToSKServer = Relationship(
        img,
        'communicates-with',
        CCserverInSK,
    )

    networkPattern = Indicator(
        name="Network Pattern",
        pattern = "[network-traffic:src_port = 443 AND network-traffic:extensions.'http-request-ext'.request_method = 'POST' AND network-traffic:extensions.'http-request-ext'.request_value = 'Agtid:']",
        pattern_type = "stix",
        description="This callback traffic is HTTP over port 443 (which is typically used for HTTPS encrypted traffic; however, the traffic is not HTTPS nor SSL encrypted). [...] The unique HTTP header 'Agtid:' contains 8 characters followed by '08x'. The same pattern can be seen in the POST content as well.",
    )

    networkPatternIndicatesImg = Relationship(
        networkPattern,
        'indicates',
        img,
    )

    networkPatternIndicatesC2Protocol = Relationship(
        networkPattern,
        'indicates',
        c2WebProtocols,
    )

    sunCss = Malware(
        name="sun.css",
        description="The sun.css file was a malicious executable with an MD5 of bd07926c72739bb7121cec8a2863ad87 and it communicated with the same communications protocol described above to the same command and control server at 180.150.228.102.",
        is_family=False,
        aliases=["bd07926c72739bb7121cec8a2863ad87"],
    )

    networkPatternIndicatesSunCss = Relationship(
        networkPattern,
        'indicates',
        sunCss,
    )

    sunCssCommunicatesWithSKServer = Relationship(
        sunCss,
        'communicates-with',
        CCserverInSK,
    )

    sunCssFromCampaign = Relationship(
        campaign,
        'uses',
        sunCss,
    )


    CCSunCssServer = Infrastructure(
        name="Server that delivered sun.css",
        description="A second related sample was also delivered from 111.118.21.105/css/sun.css on September 5, 2013.",
        aliases=["111.118.21.105"],
    )

    CCSunCssServerIP = IPv4Address(
        value="111.118.21.105",
    )

    CCSunCssServerConsistsOfIP = Relationship(
        CCSunCssServer,
        'consists-of',
        CCSunCssServerIP,
    )

    sunCssDeliveredByServer = Relationship(
        CCSunCssServer,
        'delivers',
        sunCss,
    )

    dggysyrl = Indicator(
        name="DGGYDSYRL",
        pattern = "rule APT_DeputyDog_Strings {\n meta: \n author = \"FireEye Labs\" \n version = \"1.0\" \n description = \"detects string seen in samples used in 2013-3893 0day attacks\" \n reference = \"8aba4b5184072f2a50cbc5ecfe326701\" \n strings: \n $mz = {4d 5a} \n $a = \"DGGYDSYRL\" \n condition: \n ($mz at 0) and $a \n}",
        pattern_type = "yara",
        description="These samples both had a string that may have been an artifact of the builder used to create the binaries. This string was “DGGYDSYRL”, which we refer to as “DeputyDog”. As such, we developed the following YARA signature, based on this unique attribute",
    )

    DGGYDSYRLIndicatesImg = Relationship(
        dggysyrl,
        'indicates',
        img,
    )

    DGGYDSYRLIndicatesSunCss = Relationship(
        dggysyrl,
        'indicates',
        sunCss,
    )

    potentialSamplesHashes = Indicator(
        name = "Potential Samples Hashes",
        pattern = "[file:hashes.'MD5' = '58dc05118ef8b11dcb5f5c596ab772fd' OR file:hashes.'MD5' = '4d257e569539973ab0bbafee8fb87582' OR file:hashes.'MD5' = 'dbdb1032d7bb4757d6011fb1d077856c' OR file:hashes.'MD5' = '645e29b7c6319295ae8b13ce8575dc1d' OR file:hashes.'MD5' = 'e9c73997694a897d3c6aadb26ed34797']",
        pattern_type = "stix",
        description = "We used this signature to identify 5 other potentially related samples",
    )

    hashesFoundBySignature = Relationship(
        potentialSamplesHashes,
        'related-to',
        dggysyrl,
    )

    hashesIndicateImg = Relationship(
        potentialSamplesHashes,
        'indicates',
        img,
    )

    hashesIndicateSunCss = Relationship(
        potentialSamplesHashes,
        'indicates',
        sunCss,
    )

    knownMaliciousDomains = Indicator(
        name="Known Malicious Domains",
        description="We pivoted off the command and control IP addresses used by these samples and found the following known malicious domains recently pointed to 180.150.228.102.",
        pattern_type="stix",
        pattern = "[domain-name:value = 'ea.blankchair.com ' OR domain-name:value = 'rt.blankchair.com' OR domain-name:value = 'ali.blankchair.com' OR domain-value:name = 'dll.freshdns.org']",
    )

    domainsFromHashes = Relationship(
        potentialSamplesHashes,
        'related-to',
        knownMaliciousDomains,
    )

    domainsCommunicateWithSKServer = Relationship(
        CCserverInSK,
        'related-to',
        knownMaliciousDomains,
    )

    bit9 = Infrastructure(
        name="Bit9",
        description="According to Bit9, the attackers that penetrated their network dropped two variants of the HiKit rootkit.",
    )

    bit9TargetedByCampaign = Relationship(
        campaignOnBit9,
        'targets',
        bit9,
    )

    HiKitRootkit = Malware(
        name="HiKit Rootkit",
        description="According to Bit9, the attackers that penetrated their network dropped two variants of the HiKit rootkit.",
        is_family=True,
    )

    rootKitUsedByCampaign = Relationship(
        campaignOnBit9,
        'uses',
        HiKitRootkit,
    )

    CCRootkitServer = Infrastructure(
        name="Command and Control Server for HiKit Rootkit",
        description="One of these Hitkit samples connected to a command and control server at downloadmp3server[.]servemp3[.]com that resolved to 66.153.86.14. This same IP address also hosted www[.]yahooeast[.]net, a known malicious domain, between March 6, 2012 and April 22, 2012.",
        aliases=["downloadmp3server[.]servemp3[.]com", "66.153.86.14", "www[.]yahooeast[.]net"],
    )

    HiKitRootkitCommunicatesWithCCServer = Relationship(
        HiKitRootkit,
        'communicates-with',
        CCRootkitServer,
    )

    ccrootkitserverURL = URL(
        value="downloadmp3server.servemp3.com",
    )

    ccrootkitserverIP = IPv4Address(
        value="66.153.86.14",
    )

    ccrootkitsecondurl = URL(
        value="www.yahooeast.net",
    )

    ccrootkitserverconsistsOfIP = Relationship(
        CCRootkitServer,
        'consists-of',
        ccrootkitserverIP,
    )

    ccrootkitserverconsistsOfURL = Relationship(
        CCRootkitServer,
        'consists-of',
        ccrootkitserverURL,
    )

    ccrootkitserverconsistsOfSecondURL = Relationship(
        CCRootkitServer,
        'consists-of',
        ccrootkitsecondurl,
    )

    registeredMail = Identity(
        name="654@123.com",
        description="The domain yahooeast[.]net was registered to 654@123.com. This email address was also used to register blankchair[.]com – the domain that we see was pointed to the 180.150.228.102 IP, which is the callback associated with sample 58dc05118ef8b11dcb5f5c596ab772fd, and has been already correlated back to the attack leveraging the CVE-2013-3893 zero-day vulnerability.",
    )

    registeredMailUsedToRegisterDomains = Relationship(
        registeredMail,
        'related-to',
        ccrootkitsecondurl,
    )

    registeredDomain = URL(
        value="blankchair.com",
    )

    registeredDomainrelatedToknownMaliciousDomains = Relationship(
        registeredDomain,
        'related-to',
        knownMaliciousDomains,
    )

    registeredMailUsedToRegisterKnownMaliciousDomains = Relationship(
        registeredMail,
        'related-to',
        registeredDomain,
    )

    sunCssRelatedToimg = Relationship(
        sunCss,
        'related-to',
        img,
    )

    bundle = Bundle(objects=[campaign, unknownGroup, unknownIdentity, identityOfGroup, campaignAttributedto, cveVuln, campaignTargetsVuln, internetExplorer, campaignTargetsInternetExplorer, unknownJapaneseOrg, campaignTargetsOrg, japan, orgLocatedInJapan, campaignOnBit9, attributionOfCampaign, img, imgRelatedToCampaign, hkServer, hkServerIP, hkServerconsistsOfIP, imgLocatedAtHKServer, hk, hkServerLocatedInHK, dll, dlldroppedByImg, persistenceByRegistry, persistenceUsedByImg, masquerading, masqueradingUsedByImg, c2WebProtocols, c2WebProtocolsUsedByImg, CCserverInSK, CCserverIP, CCserverconsistsOfIP, sk, serverInSKLocatedInSK, imgConnectsToSKServer, networkPattern, networkPatternIndicatesImg, networkPatternIndicatesC2Protocol, sunCss, networkPatternIndicatesSunCss, sunCssCommunicatesWithSKServer, sunCssFromCampaign, CCSunCssServer, CCSunCssServerIP, CCSunCssServerConsistsOfIP, sunCssDeliveredByServer, dggysyrl, DGGYDSYRLIndicatesImg, DGGYDSYRLIndicatesSunCss, potentialSamplesHashes, hashesFoundBySignature, hashesIndicateImg, hashesIndicateSunCss, knownMaliciousDomains, domainsFromHashes, domainsCommunicateWithSKServer, bit9, bit9TargetedByCampaign, HiKitRootkit, rootKitUsedByCampaign, CCRootkitServer, HiKitRootkitCommunicatesWithCCServer, ccrootkitserverURL, ccrootkitserverIP, ccrootkitsecondurl, ccrootkitserverconsistsOfIP, ccrootkitserverconsistsOfURL, ccrootkitserverconsistsOfSecondURL, registeredMail, registeredMailUsedToRegisterDomains, registeredDomain, registeredMailUsedToRegisterKnownMaliciousDomains, registeredDomainrelatedToknownMaliciousDomains, sunCssRelatedToimg])

    with open("stix_deputydog_DAVIDEEDOARDO_PELLEGRINO.json", "w") as f:
        f.write(bundle.serialize(pretty=True))
