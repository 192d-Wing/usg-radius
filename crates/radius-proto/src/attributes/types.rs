/// RADIUS Attribute Types as defined in RFC 2865 and related RFCs
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AttributeType {
    /// User-Name (1) - RFC 2865
    UserName = 1,
    /// User-Password (2) - RFC 2865
    UserPassword = 2,
    /// CHAP-Password (3) - RFC 2865
    ChapPassword = 3,
    /// NAS-IP-Address (4) - RFC 2865
    NasIpAddress = 4,
    /// NAS-Port (5) - RFC 2865
    NasPort = 5,
    /// Service-Type (6) - RFC 2865
    ServiceType = 6,
    /// Framed-Protocol (7) - RFC 2865
    FramedProtocol = 7,
    /// Framed-IP-Address (8) - RFC 2865
    FramedIpAddress = 8,
    /// Framed-IP-Netmask (9) - RFC 2865
    FramedIpNetmask = 9,
    /// Framed-Routing (10) - RFC 2865
    FramedRouting = 10,
    /// Filter-Id (11) - RFC 2865
    FilterId = 11,
    /// Framed-MTU (12) - RFC 2865
    FramedMtu = 12,
    /// Framed-Compression (13) - RFC 2865
    FramedCompression = 13,
    /// Login-IP-Host (14) - RFC 2865
    LoginIpHost = 14,
    /// Login-Service (15) - RFC 2865
    LoginService = 15,
    /// Login-TCP-Port (16) - RFC 2865
    LoginTcpPort = 16,
    /// Reply-Message (18) - RFC 2865
    ReplyMessage = 18,
    /// Callback-Number (19) - RFC 2865
    CallbackNumber = 19,
    /// Callback-Id (20) - RFC 2865
    CallbackId = 20,
    /// Framed-Route (22) - RFC 2865
    FramedRoute = 22,
    /// Framed-IPX-Network (23) - RFC 2865
    FramedIpxNetwork = 23,
    /// State (24) - RFC 2865
    State = 24,
    /// Class (25) - RFC 2865
    Class = 25,
    /// Vendor-Specific (26) - RFC 2865
    VendorSpecific = 26,
    /// Session-Timeout (27) - RFC 2865
    SessionTimeout = 27,
    /// Idle-Timeout (28) - RFC 2865
    IdleTimeout = 28,
    /// Termination-Action (29) - RFC 2865
    TerminationAction = 29,
    /// Called-Station-Id (30) - RFC 2865
    CalledStationId = 30,
    /// Calling-Station-Id (31) - RFC 2865
    CallingStationId = 31,
    /// NAS-Identifier (32) - RFC 2865
    NasIdentifier = 32,
    /// Proxy-State (33) - RFC 2865
    ProxyState = 33,
    /// Login-LAT-Service (34) - RFC 2865
    LoginLatService = 34,
    /// Login-LAT-Node (35) - RFC 2865
    LoginLatNode = 35,
    /// Login-LAT-Group (36) - RFC 2865
    LoginLatGroup = 36,
    /// Framed-AppleTalk-Link (37) - RFC 2865
    FramedAppleTalkLink = 37,
    /// Framed-AppleTalk-Network (38) - RFC 2865
    FramedAppleTalkNetwork = 38,
    /// Framed-AppleTalk-Zone (39) - RFC 2865
    FramedAppleTalkZone = 39,
    /// Acct-Status-Type (40) - RFC 2866
    AcctStatusType = 40,
    /// Acct-Delay-Time (41) - RFC 2866
    AcctDelayTime = 41,
    /// Acct-Input-Octets (42) - RFC 2866
    AcctInputOctets = 42,
    /// Acct-Output-Octets (43) - RFC 2866
    AcctOutputOctets = 43,
    /// Acct-Session-Id (44) - RFC 2866
    AcctSessionId = 44,
    /// Acct-Authentic (45) - RFC 2866
    AcctAuthentic = 45,
    /// Acct-Session-Time (46) - RFC 2866
    AcctSessionTime = 46,
    /// Acct-Input-Packets (47) - RFC 2866
    AcctInputPackets = 47,
    /// Acct-Output-Packets (48) - RFC 2866
    AcctOutputPackets = 48,
    /// Acct-Terminate-Cause (49) - RFC 2866
    AcctTerminateCause = 49,
    /// Acct-Multi-Session-Id (50) - RFC 2866
    AcctMultiSessionId = 50,
    /// Acct-Link-Count (51) - RFC 2866
    AcctLinkCount = 51,
    /// Acct-Input-Gigawords (52) - RFC 2869
    /// High 32 bits of 64-bit Acct-Input-Octets counter
    AcctInputGigawords = 52,
    /// Acct-Output-Gigawords (53) - RFC 2869
    /// High 32 bits of 64-bit Acct-Output-Octets counter
    AcctOutputGigawords = 53,
    /// CHAP-Challenge (60) - RFC 2865
    ChapChallenge = 60,
    /// NAS-Port-Type (61) - RFC 2865
    NasPortType = 61,
    /// Port-Limit (62) - RFC 2865
    PortLimit = 62,
    /// Login-LAT-Port (63) - RFC 2865
    LoginLatPort = 63,
    /// EAP-Message (79) - RFC 3579
    /// Encapsulates EAP packets for transport over RADIUS
    EapMessage = 79,
    /// Message-Authenticator (80) - RFC 2869
    MessageAuthenticator = 80,
    /// NAS-IPv6-Address (95) - RFC 3162
    /// The IPv6 address of the NAS, for IPv6-first deployments where the
    /// authenticator has no IPv4 NAS-IP-Address to advertise.
    NasIpv6Address = 95,
}

impl AttributeType {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(AttributeType::UserName),
            2 => Some(AttributeType::UserPassword),
            3 => Some(AttributeType::ChapPassword),
            4 => Some(AttributeType::NasIpAddress),
            5 => Some(AttributeType::NasPort),
            6 => Some(AttributeType::ServiceType),
            7 => Some(AttributeType::FramedProtocol),
            8 => Some(AttributeType::FramedIpAddress),
            9 => Some(AttributeType::FramedIpNetmask),
            10 => Some(AttributeType::FramedRouting),
            11 => Some(AttributeType::FilterId),
            12 => Some(AttributeType::FramedMtu),
            13 => Some(AttributeType::FramedCompression),
            14 => Some(AttributeType::LoginIpHost),
            15 => Some(AttributeType::LoginService),
            16 => Some(AttributeType::LoginTcpPort),
            18 => Some(AttributeType::ReplyMessage),
            19 => Some(AttributeType::CallbackNumber),
            20 => Some(AttributeType::CallbackId),
            22 => Some(AttributeType::FramedRoute),
            23 => Some(AttributeType::FramedIpxNetwork),
            24 => Some(AttributeType::State),
            25 => Some(AttributeType::Class),
            26 => Some(AttributeType::VendorSpecific),
            27 => Some(AttributeType::SessionTimeout),
            28 => Some(AttributeType::IdleTimeout),
            29 => Some(AttributeType::TerminationAction),
            30 => Some(AttributeType::CalledStationId),
            31 => Some(AttributeType::CallingStationId),
            32 => Some(AttributeType::NasIdentifier),
            33 => Some(AttributeType::ProxyState),
            34 => Some(AttributeType::LoginLatService),
            35 => Some(AttributeType::LoginLatNode),
            36 => Some(AttributeType::LoginLatGroup),
            37 => Some(AttributeType::FramedAppleTalkLink),
            38 => Some(AttributeType::FramedAppleTalkNetwork),
            39 => Some(AttributeType::FramedAppleTalkZone),
            40 => Some(AttributeType::AcctStatusType),
            41 => Some(AttributeType::AcctDelayTime),
            42 => Some(AttributeType::AcctInputOctets),
            43 => Some(AttributeType::AcctOutputOctets),
            44 => Some(AttributeType::AcctSessionId),
            45 => Some(AttributeType::AcctAuthentic),
            46 => Some(AttributeType::AcctSessionTime),
            47 => Some(AttributeType::AcctInputPackets),
            48 => Some(AttributeType::AcctOutputPackets),
            49 => Some(AttributeType::AcctTerminateCause),
            50 => Some(AttributeType::AcctMultiSessionId),
            51 => Some(AttributeType::AcctLinkCount),
            52 => Some(AttributeType::AcctInputGigawords),
            53 => Some(AttributeType::AcctOutputGigawords),
            60 => Some(AttributeType::ChapChallenge),
            61 => Some(AttributeType::NasPortType),
            62 => Some(AttributeType::PortLimit),
            63 => Some(AttributeType::LoginLatPort),
            79 => Some(AttributeType::EapMessage),
            80 => Some(AttributeType::MessageAuthenticator),
            95 => Some(AttributeType::NasIpv6Address),
            _ => None,
        }
    }

    pub fn as_u8(self) -> u8 {
        self as u8
    }
}
