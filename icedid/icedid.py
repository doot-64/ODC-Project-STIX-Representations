from stix2.v21 import *
from datetime import datetime

if __name__ == '__main__':
    icedidCampaign = Campaign(
        name="IcedID campaign",
        description="Juniper Threat Labs has been monitoring a campaign that pushes a new IcedID banking trojan. This new campaign changes tactics by injecting into msiexec.exe to conceal itself and use full steganography for downloading its modules and configurations.",
    )

    iceDId = Malware(
        name="IcedID",
        description="IcedID is a banking malware that performs Man-in-the-Browser attacks to steal financial information.",
        is_family=True,
    )

    campaignusesIcedID = Relationship(
        icedidCampaign,
        'uses',
        iceDId,
    )

    browsers = Infrastructure(
        name="Browsers",
        description="The IcedID main module, which is injected into msiexec process, watches for specific browser process names: Firefox.exe, Chrome.exe Iexplore.exe",
    )

    campaignusesBrowsers = Relationship(
        icedidCampaign,
        'targets',
        browsers,
    )

    attachmentPhishing = AttackPattern(
        name = "Spearphishing Attachment, MITRE ATT&CK T1566.001",
        description = "The first stage of the infection chain starts with phishing emails with malicious attachments",
    )

    campaignusesAttachmentPhishing = Relationship(
        icedidCampaign,
        'uses',
        attachmentPhishing,
    )


    microsoftOfficeWord = Infrastructure(
        name="Microsoft Office Word",
        description="The Word document has a malicious macro in it and, when opened by the victim, it will drop and execute a file in a specific folder",
    )


    firstLoader = Malware(
        name="First Stage Loader",
        description="The file C:\1\Whole\PFSDNSKDF.EXE that was dropped by the malicious document is another loader whose purpose is to download another IcedID loader",
        is_family=False,
    )

    wmi = Tool(
        name="Windows Management Instrumentation",
        description="It achieves this by reading a binary embedded in it and using Windows Management Instrumentation (WMI) to execute the binary",
        aliases=["WMI"],
    )


    masquerading = AttackPattern(
        name="Masquerading, MITRE ATT&CK T1036",
        description="It will then loop on the following domains, using WinHTTP queries: support.apple.com, www.intel.com, help.twitter.com, support.microsoft.com, connuwedro[.]xyz, support.oracle.com. All of the above queries are normal, except for connuwedro[.]xyz.connuwedro[.]xyz. It does this to evade detection by trying to blend to normal traffic.",
    )

    firstLoaderUsesMasquerading = Relationship(
        firstLoader,
        'uses',
        masquerading,
    )

    firstC2Domain = URL(
        value="connuwedro.xyz",
    )

    firstLoaderCommunicatesWithFirstC2Domain = Relationship(
        firstLoader,
        'communicates-with',
        firstC2Domain,
    )

    secondLoader = Malware(
        name="Second Stage Loader",
        description="This is the loader that will download the IcedID main module.",
        is_family=False,
    )

    firstLoaderDownloadsSecondLoader = Relationship(
        firstLoader,
        'downloads',
        secondLoader,
    )

    steganography = AttackPattern(
        name="Obfuscated Files or Information: Steganography, MITRE ATT&CK T1027.003",
        description="It would then decrypt this PNG file using the RC4 algorithm and execute the embedded binary. It also includes checksum checking in the code to make sure that it is the correct file. This technique is also known as steganography",
    )

    firstLoaderUsesSteganography = Relationship(
        firstLoader,
        'uses',
        steganography,
    )

    secondLoaderUsesSteganography = Relationship(
        secondLoader,
        'uses',
        steganography,
    )

    scheduledTask = AttackPattern(
        name="Scheduled Task/Job, MITRE ATT&CK T1053.005",
        description="The binary will be saved in the %APPDATA% folder and, for persistence, it creates a scheduled task that will execute every hour.",
    )

    firstLoaderUsesScheduledTask = Relationship(
        firstLoader,
        'uses',
        scheduledTask,
    )

    mainModule = Malware(
        name="IcedID Main Module",
        description="Once unpacked, it will download the IcedID main module as a PNG file from the following link: [...]",
        is_family=False,
    )

    secondLoaderDownloadsMainModule = Relationship(
        secondLoader,
        'downloads',
        mainModule,
    )

    secondC2Domain = URL(
        value = "https://cucumberz99[.]club/image?id={01XXXXXXXXXXXXXXXXXXXXXX}",
    )

    secondLoaderCommunicatesWithSecondC2Domain = Relationship(
        secondLoader,
        'communicates-with',
        secondC2Domain,
    )

    secondC2DomainIP = IPv4Address(
        value=" 31.24.224.12",
    )

    iprelatedtoSecondC2Domain = Relationship(
        secondC2Domain,
        'related-to',
        secondC2DomainIP,
    )

    obfuscationByEncryption = AttackPattern(
        name = "Obfuscated Files or Information: Encrypted/Encoded File, MITRE ATT&CK T1027.013",
        description = "The size of the image is more than 600KB and embedded in it is the encrypted IcedID main module. The encryption algorithm is RC4 and the keys are also embedded in the image at specific offset.",
    )

    mainModuleUsesObfuscationByEncryption = Relationship(
        mainModule,
        'uses',
        obfuscationByEncryption,
    )

    secondLoaderUsesObfuscationByEncryption = Relationship(
        secondLoader,
        'uses',
        obfuscationByEncryption,
    )

    systemBinaryProxyExecution = AttackPattern(
        name = "System Binary Proxy Execution: Msiexec, MITRE ATT&CK T1218.007",
        description = "Using msiexec.exe /i {random name}.msimsiexec.exe /i {random name}.msi is a simple technique to try to conceal itself and look like a normal installation of an msi application",
    )

    mainModuleUsesSystemBinaryProxyExecution = Relationship(
        mainModule,
        'uses',
        systemBinaryProxyExecution,
    )

    userExecMaliciousFile = AttackPattern(
        name = "User Execution: Malicious File, MITRE ATT&CK T1204.002",
        description = "The Word document has a malicious macro in it and, when opened by the victim, it will drop and execute a file in a specific folder.",
    )

    campaignUsesUserExecMaliciousFile = Relationship(
        icedidCampaign,
        'uses',
        userExecMaliciousFile,
    )

    userExecRelatedToPhishing = Relationship(
        userExecMaliciousFile,
        'related-to',
        attachmentPhishing,
    )

    userExecUsesWord = Relationship(
        userExecMaliciousFile,
        'uses',
        microsoftOfficeWord,
    )

    userExecUsesWMI = Relationship(
        userExecMaliciousFile,
        'uses',
        wmi,
    )

    userExecdeliversFirstLoader = Relationship(
        userExecMaliciousFile,
        'delivers',
        firstLoader,
    )

    ingressToolTransfer = AttackPattern(
        name = "Ingress Tool Transfer, MITRE ATT&CK T1105",
        description = "The code injected into an msiexec.exe sends a beacon signal to the CnC server and awaits commands. The commands include: Update the IcedID main module, Update configurations, Send bot logs to the server, Execute a shellcode from the CnC server, Collect system information, Download and execute a file from the CnC server, Execute a command and send results to the server, Reboot the client machine, Upload a file to the server, Extract passwords stored in browsers and mail applications",
    )

    mainModuleUsesIngressToolTransfer = Relationship(
        mainModule,
        'uses',
        ingressToolTransfer,
    )

    mainModuleRelatedToIcedID = Relationship(
        mainModule,
        'related-to',
        iceDId,
    )

    browserHijacking = AttackPattern(
        name = "Browser Hijacking, MITRE ATT&CK T1185",
        description = "The IcedID main module, which is injected into msiexec process, watches for specific browser process names: Firefox.exe, Chrome.exe Iexplore.exe. [...], all connections to the browser are proxied to msiexec.exe and it achieves full control of the browser.",
    )

    mainModuleUsesBrowserHijacking = Relationship(
        mainModule,
        'uses',
        browserHijacking,
    )

    sitesTargeted = Identity(
        name="Targeted Sites",
        description = "It will monitor browser activity related to financial transactions and inject forms on the fly to try to steal credit card details. Among the banks and financial-related services it targets are the following: Amazon.com, American Express, AT&T, Bank Of America, Capital One, Chase, CIBC, Comeriсa, Dell, Discover, Dollar Bank, eBay, Erie Bank, E-Trade, Frost Bank, Halifax UK, Hancock Bank, Huntington Bank, J.P. Morgan, Lloyds Bank, M&T bank, Centennial Bank, PNC, RBC, Charles Schwab, SunTrust Bank, Synovus, T-Mobile, Union Bank, USAA, US Bank, Verizon Wireless, Wells Fargo",
    )

    browserHijackingTargetsSites = Relationship(
        browserHijacking,
        'targets',
        sitesTargeted,
    )

    trickBot = Malware(
        name="TrickBot",
        description="The keyword “Internet Widgits Pty Ltd” is also being used by Trickbot, another banking malware, and it is believed that Trickbot and IcedID are cousins.",
        is_family=False,
    )

    selfSignedCertificate = Indicator(
        name = "Self-Signed Certificate",
        description = "IcedID uses TLS in all of its communication but the certificate is self-signed. They can be spotted, as they use this kind of a self-signed certificate. The keyword “Internet Widgits Pty Ltd” is also being used by Trickbot, another banking malware, and it is believed that Trickbot and IcedID are cousins.",
        pattern_type = "stix",
        pattern = "[x509-certificate:issuer='CN=Internet Widgits Pty Ltd']",
    )

    selfSignedCertificateIndicatesCampaign = Relationship(
        selfSignedCertificate,
        'indicates',
        icedidCampaign,
    )

    selfSignedCertificateIndicatesTrickBot = Relationship(
        selfSignedCertificate,
        'indicates',
        trickBot,
    )

    icedIDandTrickBot = Relationship(
        iceDId,
        'related-to',
        trickBot,
    )

    encryptedChannel = AttackPattern(
        name = "Encrypted Channel: Asymmetric Cryptography, MITRE ATT&CK T1573.002",
        description = "IcedID uses TLS in all of its communication but the certificate is self-signed. They can be spotted, as they use this kind of a self-signed certificate.",
    )

    campaignUsesEncryptedChannel = Relationship(
        icedidCampaign,
        'uses',
        encryptedChannel,
    )

    firstStageLoaderHashes = Indicator(
        name = "First Stage Loader Hashes",
        description = "Provided IOC hashes for the first stage loader",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = '822a8e3dfa14cd7aaac749dc0515c35cf20632717e191568ba5daf137db7ec17' OR file:hashes.'SHA-256' = '74d6e374d7958e70c6733b6c17e2f0d79b629e172aaf385c142c76678647f3b8' OR file:hashes.'SHA-256' = '436b0c94c1be2be6b328830568ef7f031b45bf6d2377fa9f4b1f872ffb39b369' OR file:hashes.'SHA-256' = '4ca8c054641c1f11c033cc20ebae77c4a41853e2fe693ecf4b93a9719b624c1e' OR file:hashes.'SHA-256' = 'afdb9b4c2e9a47a137a385e41a47727c0a04b2001aab60d6b3e099d0faf4ddef' OR file:hashes.'SHA-256' = 'e4f89d4ff1d26e0959c7147df641c6dae3e0d15729a5fd275857e98225b44245' OR file:hashes.'SHA-256' = '3ff97578adea9f45bccea091234c5ccee6a12b3c52e7e29195a45e3c191aa926' OR file:hashes.'SHA-256' = 'e15744eb13666670ad3cf256c31df57a01c40f355a0f8a592294187d4fedc257' OR file:hashes.'SHA-256' = '454ff6a5ebf01fc7d9c1ced5b081d582d11119ab9b49fc06ccaf22b1b0259c23' OR file:hashes.'SHA-256' = '54197c58c9693580c8ca961d8ff326cbad7688b23627114f7437c59fede46e82' OR file:hashes.'SHA-256' = 'f1bf5ef89f644b1558dd54e68148e60310d537ca45c2daae2b410c30540d7de6' OR file:hashes.'SHA-256' = 'e48e4e74dc7e67523878a2cf68b2ce72b5e5c999897e075d6b993e41c81f4174' OR file:hashes.'SHA-256' = 'ef2ab4bc4ee63dd1b9f04a56fe727a87f56ddd476bc1cd72c78f4d31abff322a' OR file:hashes.'SHA-256' = 'fd11736701395813459091b6d07878c52b448a4d9a5825517a0308fbfe6fa070' OR file:hashes.'SHA-256' = '9979063dae01bdfffd946ed012e69fabb82be3795323a52b06532b42b0f59609' OR file:hashes.'SHA-256' = '09c3ada49c47af20854d87fbb76a24263d759f93f8de7e5af88549111ce55dda' OR file:hashes.'SHA-256' = '10ab8bfff505a3add9537bf742ede32f985e9f1ecc3a8afca99005b7255bca1b' OR file:hashes.'SHA-256' = 'a6e0690db18e89187c2a9b0924585264606482dfdd9ac97c744bb649615ced65' OR file:hashes.'SHA-256' = '1e988d02dedc8307c518e6bc2c6f8be14e4f0cd941972622deebcd90a6f09013' OR file:hashes.'SHA-256' = 'f4fecef8cd7c7688d98ff168e137c70d98f01866114e552ede71aa28e2088018' OR file:hashes.'SHA-256' = 'b0dc0a79862585b381afb61b05640276d51001961ddf9608703195bc183f1f06' OR file:hashes.'SHA-256' = '8664c34e72bc78098668331faa8f5113ad798a29c085662a0a9d83c4598843b2' OR file:hashes.'SHA-256' = '404650dbf9d8d4fcf844f529b042b895979f3a87334fb97925805c8072725ea8' OR file:hashes.'SHA-256' = 'f5d8de500a504f6493af21ac67f50f5a4de5d6371e36c3a2251ac098f256187b' OR file:hashes.'SHA-256' = '385a41aaa192a8cd56bc35b1841a8e4a31f4cae1d5b68542ae7584b6420d363e' OR file:hashes.'SHA-256' = '55e1ba8683bb6b1d2a4f8b16b16ede25943d66e5884c9793f8c078614d12d9c4' OR file:hashes.'SHA-256' = 'dea7eaee76df0fa27ae5ddd2988222b8afefd73ff80f5a5a14108cb499b85a23' OR file:hashes.'SHA-256' = 'f30f283832f7a371c2c23cb2b5801e71bd33856c026480ab9165e584300fa3b3' OR file:hashes.'SHA-256' = '57ea3ae558efce33cf28a5cefa26e93a07186e5cdf799d5d066edaf581f66706' OR file:hashes.'SHA-256' = '2e294fbc75cefcbece50a3e57730212fd7672a4cce487db0bdfd241032a5bcb7' OR file:hashes.'SHA-256' = '3a11e16512b0f4c1380c5f94ff65312c421955c5693ea73260e2274eb34470c8']",
    )

    firstStageLoaderHashesIndicatesFirstStageLoader = Relationship(
        firstStageLoaderHashes,
        'indicates',
        firstLoader,
    )

    downloaderDomains = Indicator(
        name = "Downloader Domains",
        description = "Provided IOC domains for the downloader",
        pattern_type = "stix",
        pattern = "[domain-name:value = '2pillsofhunderts.pw' OR domain-name:value = '3chickens.pw' OR domain-name:value = '3glanzepages.top' OR domain-name:value = 'bividilli.xyz' OR domain-name:value = 'carpetkisa.xyz' OR domain-name:value = 'connuwedro.xyz' OR domain-name:value = 'feminization.xyz' OR domain-name:value = 'filacolonel.xyz' OR domain-name:value = 'fredoferodo.top' OR domain-name:value = 'frenchfries8.top' OR domain-name:value = 'ghefgekil.club' OR domain-name:value = 'gigakolors.club' OR domain-name:value = 'goodcolonell.xyz' OR domain-name:value = 'groggypirogy.top' OR domain-name:value = 'hinkaly.club' OR domain-name:value = 'karantino.xyz' OR domain-name:value = 'kassadesada.top' OR domain-name:value = 'knockaddress.xyz' OR domain-name:value = 'knockdomain.xyz' OR domain-name:value = 'lokolojazz.club' OR domain-name:value = 'pyramide33.pw' OR domain-name:value = 'siffersniffer.best' OR domain-name:value = 'silkycow.pw' OR domain-name:value = 'stuffed8tomatoes.club' OR domain-name:value = 'testermeisterz.top' OR domain-name:value = 'tryfreder.xyz' OR domain-name:value = 'vodkahater.xyz' OR domain-name:value = 'yahzdaje2.website' OR domain-name:value = 'zajjizev.club']",
    )

    downloaderDomainsIndicatesSecondStageLoader = Relationship(
        downloaderDomains,
        'indicates',
        secondLoader,
    )

    downloaderDomainsIndicatesFirstStageLoader = Relationship(
        downloaderDomains,
        'indicates',
        firstLoader,
    )

    firstC2DomainrelatedtoDownloaderDomains = Relationship(
        firstC2Domain,
        'related-to',
        downloaderDomains,
    )

    secondLoaderHashes = Indicator(
        name = "Second Loader Hashes",
        description = "Provided IOC hashes for the second loader",
        pattern_type = "stix",
        pattern = "[file:hashes.'SHA-256' = 'c35dd2a034376c5f0f22f0e708dc773af8ee5baf83e2a4749f6f9d374338cd8e' OR file:hashes.'SHA-256' = '014b422e6c1bc23db2b5898dd0c49ac61fbac174c1e0d916f68b41cfb535cdb5' OR file:hashes.'SHA-256' = '015243f1e4fa8c0eabf86ae752056e2876e50b3b67e95fa486451904d311580d' OR file:hashes.'SHA-256' = '021cae01a3e9e734ca0b96c30d7d358b7b41c84565c95b448771de56ae85621e' OR file:hashes.'SHA-256' = '063ed7054f8f7d72cb34f9a37725b5974fdafc743c338b07bc7b0b2ab6a212e1' OR file:hashes.'SHA-256' = '06d21126d11e3fd07c66c7f9c096f80fa8046b5e1bf4370187401890fdf4fd5c' OR file:hashes.'SHA-256' = '07671c10dd548d8a535939c0282d6710b07c8e2e8e7efa466de09202d02cd550' OR file:hashes.'SHA-256' = '08bb93772c22c2842e968f5ad3753062530c4fcee87110afe46d95889c484dfb' OR file:hashes.'SHA-256' = '0b0b92a625911a7065cf0e48d470acac71290c6832363a715b1f46aff01fe4c8' OR file:hashes.'SHA-256' = '0c69c38b7d436280492807d77a308f2eec5007afc0683aa206358db91c116def' OR file:hashes.'SHA-256' = '15041d3408372977905bda10cbccd9a86135eb441152968299e3c05ebcbae93c' OR file:hashes.'SHA-256' = '16ae5983ca6e3f7bf893e0ba9ef44f2f46270a717abed860fdd56a7ad5cc8f77' OR file:hashes.'SHA-256' = '16efa114618cdf5426f514c79597d29fe0ced79f32c5b56985cf2820854d7a36' OR file:hashes.'SHA-256' = '18726b5405dc2f8159f3496939c5df3ca742ff271a2dd294b033433203f35eb3' OR file:hashes.'SHA-256' = '1faa5ce90b3496c6938f3fe3a25f89939a297254a183fb75a8d58abfcc9fddfd' OR file:hashes.'SHA-256' = '1fd7fea39524f3e5edcd0d41e9b2f9c9fa639ec22e80bacd173b7744b4a05601' OR file:hashes.'SHA-256' = '2660abba68d81b50c997b787a98484e1eeea47269cdbe1f5ae87e6ac086b5237' OR file:hashes.'SHA-256' = '26e0468acd186e744e895f116d14e20179d74f61fa819b5984442cac51f07b00' OR file:hashes.'SHA-256' = '284aaafa51b1131e6656b270af6c3a032cf454ead1d5f0a5926ebe22772cf0d9' OR file:hashes.'SHA-256' = '2aab4bb300e505e278a20a2aa804c9ba5920c2513b425440b1c818d53a0dd672' OR file:hashes.'SHA-256' = '2b7ccec0aa1d9f09fb7d17034acf00b0e96dd47ecabe767b419a474a0854e42c' OR file:hashes.'SHA-256' = '2ba7ecdb95e16f4af77d2cb09e301306c2115350da49e36afa26a365fceb110c' OR file:hashes.'SHA-256' = '2bfa9f878dce2de087715d7986e369197aecd166a635c80a2f2c39a9b8e327fd' OR file:hashes.'SHA-256' = '2e1d4c5755845068909b229939511d6a9a0b7b5df6801f44a3a3a274d6048804' OR file:hashes.'SHA-256' = '32efada9f1ba73c5ded10c2338fe261e0e4c997f48696464978af942c9f2599f' OR file:hashes.'SHA-256' = '3391f3da58a8b440b0c58084a280cf9cac28395ecf87c8307d5efb9d66b6164f' OR file:hashes.'SHA-256' = '359ea0e4217bea81d92e6e274681ab7df24caaaaa0e6ad412e2f9045113c6ea1' OR file:hashes.'SHA-256' = '386becd1260847d03958dbc82b5f6565e2855ed5439eef34b57678410877174e' OR file:hashes.'SHA-256' = '396a445f43fc63122543cbb16fe2919e19aa2371f7165c3817acac7885701afd' OR file:hashes.'SHA-256' = '3a09fb755bb94cfbd598d16c3a8dd430be51a1eed9dc5791a8f07bab6e2bc284' OR file:hashes.'SHA-256' = '4267ef18ddeb15cf6920e2bc89f5c9247b6f554112a124ee2211281ce98ec04f' OR file:hashes.'SHA-256' = '43275d3fdf60216df9c0151b11db2896a1dd56b9e7267ed6db78f4ef21cb8b46' OR file:hashes.'SHA-256' = '44271a7612f1b32ed5fb0bac211992ea5e5c243710b9b4e8ad83f08af6a6cf4f' OR file:hashes.'SHA-256' = '46a19f4b4dcfcb51b0db1718ad6d64bf0eb28170c61421e87e7edc07facd329c' OR file:hashes.'SHA-256' = '48293a9ec8e7d12370cb1c1266653053ad5861761c74c437b2350aa909490327' OR file:hashes.'SHA-256' = '4aec02ec7bc4ff2fbde2e36eb40411bcd69ee2dd9abeaccdd306a3aca8f5ad1a' OR file:hashes.'SHA-256' = '4e7161be03f206c1b086bb15b47470ec1c9381302eb34d0e76915496aec77193' OR file:hashes.'SHA-256' = '50cee93429653fd24d534c31c52a94e71b4fdc1e5409f8ac4ae2a81210ea12e2' OR file:hashes.'SHA-256' = '5542f9cc78b5aa2901c2187f1dcee8e214aca20465c81c4da51035477d19287c' OR file:hashes.'SHA-256' = '55acf5558ef68bd26148074c6f916311ea760edc6cbd136973ea638c98606a93' OR file:hashes.'SHA-256' = '57100de2a289e45824f5cbaf8074e3f6e543eb2aa9a18584b1a007c7b4ddaa48' OR file:hashes.'SHA-256' = '5c91d58ad4b5f1536c2548ac3080f02155df555025c634659cb15dfc5ec2143f' OR file:hashes.'SHA-256' = '5de3eb250030550512c0ce92923ff30bc16529a45a5f24c624e9d7c7a4e0c1e4' OR file:hashes.'SHA-256' = '5e38dcb3632d7ac183bded4662c139db2f54c104ae1efda75b62b0bd0b9882f1' OR file:hashes.'SHA-256' = '61ca03447437e224ac301c56a72684a3c08310a3b850aff69952d124b488bc4e' OR file:hashes.'SHA-256' = '696ef2c7fb064b293173bae309c1cabe3d2dd2d1a1becab040acb05c82022c2e' OR file:hashes.'SHA-256' = '69fced2e42d5fcb3b0ade5ebc81359c1f8c2e51935db74f40c94fb5c646130d9' OR file:hashes.'SHA-256' = '6c02225c8a5ae583e738417866bc2f66636834ff025749da7f36ea639cbcacb6' OR file:hashes.'SHA-256' = '6c878a7145e9f783f28b665207d9d180d04d0fe8e42bb2ff594faf5692f25ebd' OR file:hashes.'SHA-256' = '72d4df9bca3cdf2074ffa84580c01fa425d528be54f331c59eb27a12a3736093' OR file:hashes.'SHA-256' = '7a41e722fb6fd0067378cba5e4ddcb9c122205f41eee22204ce83af63a89b4fe' OR file:hashes.'SHA-256' = '7babfaa95153f3f4c06630ff30d225760ae4a50e75764b9e049d8d70bfd88107' OR file:hashes.'SHA-256' = '7f45cf09a572799af51ea935b95b185c05e13f749c9f1e2a2d41f8001c76487e' OR file:hashes.'SHA-256' = '7fb71830442acb35dd86e559d632d7a14c21b60639203c61d371831b78dde6e3' OR file:hashes.'SHA-256' = '81869e50ce5599cab247458445cc36b5a3108398f1ed520d29a4e7395a81afe0' OR file:hashes.'SHA-256' = '82f48defd2de04d87de86ce8e584c6cb1bad8581d99e65ae99b58ef96f623089' OR file:hashes.'SHA-256' = '87322aed33bf01ca618ad94e1d6a042bae91c978fabfb3e7fcccfa75a64c5d6a' OR file:hashes.'SHA-256' = '882a9e7001dd1618c593f68e11f77c8e86239f610283e88981eecab93b5158a7' OR file:hashes.'SHA-256' = '8831ac358046286facb6ca2643927aa837907937d1895ee3b73472c58bf3ef2c' OR file:hashes.'SHA-256' = '8a4b045d11a898ced073e564e601b9624ace121be688ec20f31d56bc1edfc377' OR file:hashes.'SHA-256' = '8a60949ae63dd0d80a49485a7a2ce1a29505ed76eee018ef12d28ac70bece07d' OR file:hashes.'SHA-256' = '8d1b83eff1b3c604365fd29de1bb43204852de842c0bb148975fe7a7485310e4' OR file:hashes.'SHA-256' = '8d97b91ce882f9405b7a7de5b1f08fdef0a0db4303977140546ebff72af1bc7f' OR file:hashes.'SHA-256' = '9118ba30cefcc565be8a9ba85ee66da7670f18b08ec3cb205be80e78bf64f5fa' OR file:hashes.'SHA-256' = '927a8d1445750400db3850d0b2dc3522b0f373098385373efa3d7762120f3689' OR file:hashes.'SHA-256' = '949d06fb921d1e32be7232933d0578c086112c5b782640cd5b9a6b6570f27bf7' OR file:hashes.'SHA-256' = '961588c90fe84a65e9aff3b98a95cd46d581add783ce639065665a01a16530f5' OR file:hashes.'SHA-256' = '961ced78105cf07255f79dd7ad0ecaa2360b6ac08264acfb22d927e3d7f441c4' OR file:hashes.'SHA-256' = '96c825103005a025660b5d32002a636d2242801949d0b970a77625be268a8cd5' OR file:hashes.'SHA-256' = '97a32b419c28bfa62220fc8a7c715a899bf84484e34a75ee97c766d7d43b2b4a' OR file:hashes.'SHA-256' = '9c19493c7ecb8067a0a52e089b819f53adf6a1f6b0535b42f1e5325a789125d9' OR file:hashes.'SHA-256' = '9caa061ca9619b215e657357f368e9fa7d64e402c13d55b76578c5acddd25aab' OR file:hashes.'SHA-256' = '9ff86c3e52aea34f885d1f298ee9e448368d941bf122f61278b6d50addb36744' OR file:hashes.'SHA-256' = 'a234c29baff478276e9ae616046d98ca1ed57311616691a7e048e0af6d9c1c44' OR file:hashes.'SHA-256' = 'a24fe24beb66aef2978017939f29a7eb3cbd1ca3d210a9834cae112ba86d075b' OR file:hashes.'SHA-256' = 'a299a3d1d838adc37ea985039650b7b32428d3787a0b7e31feeafcb831eb984d' OR file:hashes.'SHA-256' = 'a3d5871579dd194d86e5af84e306c38d27703bbe9b7e7d4209b68cafd21464e6' OR file:hashes.'SHA-256' = 'a55a668b4180ea3cd58472dc0fb9b45dd92c09cf049644cbc25f5b50a9d05001' OR file:hashes.'SHA-256' = 'a6fa541a097faa1f61b7085eb52b46bd893944f93a8bd20205118b1b7b802fd4' OR file:hashes.'SHA-256' = 'a9129fc61d0ea9a2756c64febfc486895e37312e5ff8eabd16b7ff201bb90e7c' OR file:hashes.'SHA-256' = 'ad58f15ff69ee59a32ae410acd564cd4b53a5cfaea6ede136046cee12f1c0b59' OR file:hashes.'SHA-256' = 'adc05158b29dcb3f96532e526bdb296cb5e424a96e6f7b83b6c0b82b811d2740' OR file:hashes.'SHA-256' = 'ade52f993013635afe7eaf0d91cc0521b97f3de1ca541882bde3ee94c872982f' OR file:hashes.'SHA-256' = 'ade6356fb4f693664d5dcb54c3e1ca6a9013ef653b473bdd7a2e1407bddc6193' OR file:hashes.'SHA-256' = 'b6c2ebd3be005f672514cbc3ab320b9dd887f17b6bc14bd5bd34adc5a951ef17' OR file:hashes.'SHA-256' = 'b78d867fa64b9c7f8ad19b6fc4ec934b3c1c13e6fe080c84d4685629f18a0de6' OR file:hashes.'SHA-256' = 'b7de965c5e2cfef42def39f124d37d1302ea93b91aa394d2cf41cfa7df2607e6' OR file:hashes.'SHA-256' = 'b8768315d048093fc216c8921dcc392628d977ea97efcf352e5a89035635ffdd' OR file:hashes.'SHA-256' = 'b90881ea27e45a5beec5abdcfa7f83709b8ca02b9a533a7d1325df059522d21c' OR file:hashes.'SHA-256' = 'bdb743a2f2cd6ef45f9d0c97ec8feb590831d108bc7d434b5f65e87ab4be9746' OR file:hashes.'SHA-256' = 'bf4da5aa980f12573157473f694210276a72d4f26cb7bfce38b84be5e33fd195' OR file:hashes.'SHA-256' = 'c57c797dc857427dd9d34524f32897cd001dd0d5526b7ae382158989a57541a4' OR file:hashes.'SHA-256' = 'c7ef139a5291a1e2b70551f4fc8290a4bc963ba4bf36101aa787eab21fa2aa83' OR file:hashes.'SHA-256' = 'ca59caa3199f6ec24cead3e4b705f8a22c5b78f3b62f84791c03784e3b55993a' OR file:hashes.'SHA-256' = 'cba5edb9a6a3c25b635a050492d6f9e6cd69f916ec57f4787e5b2e3a8356182c' OR file:hashes.'SHA-256' = 'cddb94b07baa8502aa7ec15815606d89630fc6d62790a42fb9b0aabe76700de1' OR file:hashes.'SHA-256' = 'cebb538862dcfa960e48d09a7d44dc0b096cff66bd61606f54949433ce94ff7f' OR file:hashes.'SHA-256' = 'ced9b6411f4c3db104f9b25b9c638f5874097219152c1800fd7988f03da15b29' OR file:hashes.'SHA-256' = 'cf79819a5ab92e53568736463be90254504a60a07543f6d1d14148808940519e' OR file:hashes.'SHA-256' = 'd5e2868d0eaab6056d49a9f2a35842e0d2390e84beed0e352ed3cb19f3dc380e' OR file:hashes.'SHA-256' = 'd8619ab7066af14878548719f8737ec110df19badbdd3d6394a941127c268d19' OR file:hashes.'SHA-256' = 'd9ea9d94359fa3e8edda3e1e659925f25e7003a8254b52229800220b67b651bb' OR file:hashes.'SHA-256' = 'df0b5d6ca7ba81e22d98e1f4dafe4d222ce496c31299e4189d8d773d9b70d6ec' OR file:hashes.'SHA-256' = 'df30ccce6ec03c03e2e1ca041200267cd3b708946cc2f18577dfee7ea351272c' OR file:hashes.'SHA-256' = 'e0d78b3a64c0d256d4be7c2b959fb8ce49950bd2abb975aa35b6421d1be6e9e9' OR file:hashes.'SHA-256' = 'e1a2490b48fe59d053f5d486af00f72b2973d71ea87496c8158cd60e72f9b386' OR file:hashes.'SHA-256' = 'e48d5ea33faf98eb5264896ad8fdc72cb53998282c871edd189a615096c3ec56' OR file:hashes.'SHA-256' = 'e624144b6c38455eb528fa2fdb1631b822608bde5eacbec097a18ef3e54c40b7' OR file:hashes.'SHA-256' = 'e6c21816d712973a1e6b615164ed475dc58694afb88c69ec61c81bba7daa1297' OR file:hashes.'SHA-256' = 'e7bcd48b2948a278876343900aa3ee30cab266e6fa26c3031eee5dd846983ce2' OR file:hashes.'SHA-256' = 'ea6cecdaef1dde96281060a27ba65beb4079c04313697f60073be1196af7ecc6' OR file:hashes.'SHA-256' = 'ebac2e585e43af2737f6bdf291b93e88dfddb64efc97ed5c514afd2848814515' OR file:hashes.'SHA-256' = 'ec1f379b1032fc9f8acb9785d83978e3197dda7a3ab42ff697529c8cb7dfa579' OR file:hashes.'SHA-256' = 'ec56f0a98216810fe2706d04c9c7350e3e125b3e3207ccde0442f91fb8804921' OR file:hashes.'SHA-256' = 'ee1bc25f45c431fce214dc0f0838fa8969142296a20c3887282750521ee41518' OR file:hashes.'SHA-256' = 'ee29459f34c2d80b939ee41268e4c7f09eb639b2f4b97346ef10722d999323ec' OR file:hashes.'SHA-256' = 'eeb4caedbe98e144bf7e30165f9c4e16525b964927af3dda94616abe18d0c476' OR file:hashes.'SHA-256' = 'ef25d0b852fc83e6843c0ad7e081cbcc4541a4a0713f81a8261375f451585f6b' OR file:hashes.'SHA-256' = 'f02094836adc271479734dfd5326a74f79a7545b679df03e03e339cd5db0c116' OR file:hashes.'SHA-256' = 'f3ba5d0b27ff406dcd1c624aee919f394d231b878f040ec23e36c7f0cf81df99' OR file:hashes.'SHA-256' = 'f77ff256c9e359a4d6fb7dc28aebaef987c919c54b001494e1624df09b73fb26' OR file:hashes.'SHA-256' = 'f78bfa34d031119443d2e4fac2c291cd2e16fe932cec448cd88b8f8592aa76d5' OR file:hashes.'SHA-256' = 'f7b5c622fd5f295615df5af2ad883f5946ad2f72002c4c3be1a9ad0df7c2b2e5' OR file:hashes.'SHA-256' = 'fb82d8338af07adaa5d46c372e5597015ccfb0f6e48dd9dbfceb282d5e8781b7' OR file:hashes.'SHA-256' = 'fd56107c80cef6e7b7493d01175d6801ba28c0393c4f36f440bc97c8cf5f0e3d']",
    )

    secondLoaderHashesIndicatesSecondLoader = Relationship(
        secondLoaderHashes,
        'indicates',
        secondLoader,
    )

    c2Domains = Indicator(
        name = "C2 Domains",
        description = "Provided IOC domains for the C2 pattern",
        pattern_type = "stix",
        pattern = "[domain-name:value = '30miles.xyz' OR domain-name:value = 'antivarevare.club' OR domain-name:value = 'antivarevare.pw' OR domain-name:value = 'bavadivaclub.club' OR domain-name:value = 'beradocolon.top' OR domain-name:value = 'bluekit.pw' OR domain-name:value = 'bonwes.bid' OR domain-name:value = 'bredretre.uno' OR domain-name:value = 'carztesla.xyz' OR domain-name:value = 'chumocarz.club' OR domain-name:value = 'citytrallbus.xyz' OR domain-name:value = 'colocarantino.xyz' OR domain-name:value = 'cosacasa.top' OR domain-name:value = 'costacolonel.club' OR domain-name:value = 'costamustero.pw' OR domain-name:value = 'coucarachiz.top' OR domain-name:value = 'cozyappt.club' OR domain-name:value = 'crossbones.email' OR domain-name:value = 'cryptocrio.pw' OR domain-name:value = 'cryptocrio.top' OR domain-name:value = 'cucumberz99.club' OR domain-name:value = 'dayafterthe.xyz' OR domain-name:value = 'dezisenkor.club' OR domain-name:value = 'docccutime.xyz' OR domain-name:value = 'emergencytoolz.pw' OR domain-name:value = 'extraordinarycurc.club' OR domain-name:value = 'fekilopol.xyz' OR domain-name:value = 'fidelliware.pw' OR domain-name:value = 'filacolonel.site' OR domain-name:value = 'filteroggy.pw' OR domain-name:value = 'fishmak.pw' OR domain-name:value = 'flighfinder.xyz' OR domain-name:value = 'flightslots.online' OR domain-name:value = 'forwardnogi.pw' OR domain-name:value = 'fullplainefares.club' OR domain-name:value = 'gerenada.club' OR domain-name:value = 'glassyradua.xyz' OR domain-name:value = 'goodservers.top' OR domain-name:value = 'herekeder.best' OR domain-name:value = 'instarobotics.club' OR domain-name:value = 'loacorecoder.club' OR domain-name:value = 'menosmeno.best' OR domain-name:value = 'millogorillo.top' OR domain-name:value = 'nadalia.top' OR domain-name:value = 'northdestrickt.top' OR domain-name:value = 'oggytarakan.club' OR domain-name:value = 'oggythecoucca.xyz' OR domain-name:value = 'polymorphis.top' OR domain-name:value = 'pravizzillo.club' OR domain-name:value = 'pravizzillo.email' OR domain-name:value = 'presserdresser.best' OR domain-name:value = 'pythonfinder.top' OR domain-name:value = 'safebanktest.top' OR domain-name:value = 'seguridadcolonel.club' OR domain-name:value = 'sharedocar.xyz' OR domain-name:value = 'smallhole.club' OR domain-name:value = 'svaerossi.pw' OR domain-name:value = 'tourdayly.top' OR domain-name:value = 'trythisone2.best' OR domain-name:value = 'uxozhuki.pw' OR domain-name:value = 'vereseptem.pw' OR domain-name:value = 'withoutemblems.top']",
    )

    c2DomainsIndicatesCampaign = Relationship(
        c2Domains,
        'indicates',
        icedidCampaign,
    )

    secondC2domainRelatedToC2Domains = Relationship(
        secondC2Domain,
        'related-to',
        c2Domains,
    )

    bundle = Bundle(objects=[icedidCampaign, iceDId, campaignusesIcedID, browsers, campaignusesBrowsers, attachmentPhishing, iprelatedtoSecondC2Domain, mainModuleRelatedToIcedID, downloaderDomainsIndicatesFirstStageLoader, secondLoaderUsesObfuscationByEncryption, campaignusesAttachmentPhishing, microsoftOfficeWord, userExecUsesWord, firstLoader, userExecdeliversFirstLoader, wmi, userExecUsesWMI, masquerading, firstLoaderUsesMasquerading, firstC2Domain, firstLoaderCommunicatesWithFirstC2Domain, secondLoader, firstLoaderDownloadsSecondLoader, steganography, firstLoaderUsesSteganography, secondLoaderUsesSteganography, scheduledTask, firstLoaderUsesScheduledTask, mainModule, secondLoaderDownloadsMainModule, secondC2Domain, secondLoaderCommunicatesWithSecondC2Domain, secondC2DomainIP, obfuscationByEncryption, mainModuleUsesObfuscationByEncryption, systemBinaryProxyExecution, mainModuleUsesSystemBinaryProxyExecution, userExecMaliciousFile, campaignUsesUserExecMaliciousFile, userExecRelatedToPhishing, ingressToolTransfer, mainModuleUsesIngressToolTransfer, browserHijacking, mainModuleUsesBrowserHijacking, sitesTargeted, browserHijackingTargetsSites, trickBot, selfSignedCertificate, selfSignedCertificateIndicatesCampaign, selfSignedCertificateIndicatesTrickBot, icedIDandTrickBot, encryptedChannel, campaignUsesEncryptedChannel, firstStageLoaderHashes, firstStageLoaderHashesIndicatesFirstStageLoader, downloaderDomains, downloaderDomainsIndicatesSecondStageLoader, firstC2DomainrelatedtoDownloaderDomains, secondLoaderHashes, secondLoaderHashesIndicatesSecondLoader, c2Domains, c2DomainsIndicatesCampaign, secondC2domainRelatedToC2Domains])

    with open("stix_icedid_DAVIDEEDOARDO_PELLEGRINO.json", "w") as f:
        f.write(bundle.serialize(pretty=True))
