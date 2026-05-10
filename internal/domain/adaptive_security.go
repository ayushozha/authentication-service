package domain

import "time"

const (
	RiskLevelLow      = "low"
	RiskLevelMedium   = "medium"
	RiskLevelHigh     = "high"
	RiskLevelCritical = "critical"

	MFAModeOff      = "off"
	MFAModeAllow    = "allow"
	MFAModeRequired = "required"
	MFAModeAdaptive = "adaptive"

	StepUpModeOff       = "off"
	StepUpModeChallenge = "challenge"
	StepUpModeBlock     = "block"
	StepUpModeNotify    = "notify"

	MFAFactorTOTP         = "totp"
	MFAFactorRecoveryCode = "recovery_code"

	SecurityActionLogin                    = "auth.login"
	SecurityActionPasswordChange           = "auth.password_change"
	SecurityActionOrganizationUpdate       = "organization.update"
	SecurityActionOrganizationMemberRole   = "organization.member.role_change"
	SecurityActionOrganizationMemberRemove = "organization.member.remove"
	SecurityActionOrganizationTokenIssue   = "organization.token.issue"
	SecurityActionClientKeyRotate          = "client.key.rotate"
	SecurityActionServiceAccountKeyRotate  = "service_account.key.rotate"
	SecurityActionSCIMTokenRotate          = "scim.token.rotate"
	SecurityActionAuditExport              = "audit.export"
	SecurityActionBillingChange            = "billing.change"
	SecurityActionDataExport               = "data.export"
)

type MFAPolicy struct {
	Mode                string   `json:"mode"`
	Factors             []string `json:"factors,omitempty"`
	ChallengeRiskLevel  string   `json:"challenge_risk_level,omitempty"`
	BlockRiskLevel      string   `json:"block_risk_level,omitempty"`
	RememberDeviceDays  int      `json:"remember_device_days,omitempty"`
	TrustedDeviceBypass bool     `json:"trusted_device_bypass,omitempty"`
	EnrollmentRequired  bool     `json:"enrollment_required,omitempty"`
}

type RiskPolicy struct {
	ChallengeLevel          string   `json:"challenge_level,omitempty"`
	BlockLevel              string   `json:"block_level,omitempty"`
	FailedVelocityThreshold int      `json:"failed_velocity_threshold,omitempty"`
	TrustedIPCidrs          []string `json:"trusted_ip_cidrs,omitempty"`
	BlockedIPCidrs          []string `json:"blocked_ip_cidrs,omitempty"`
	TorIPCidrs              []string `json:"tor_ip_cidrs,omitempty"`
	VPNASNs                 []int    `json:"vpn_asns,omitempty"`
	HighRiskASNs            []int    `json:"high_risk_asns,omitempty"`
}

type StepUpActionPolicy struct {
	Mode               string   `json:"mode"`
	Factors            []string `json:"factors,omitempty"`
	RiskChallengeLevel string   `json:"risk_challenge_level,omitempty"`
	RiskBlockLevel     string   `json:"risk_block_level,omitempty"`
	MaxAgeSeconds      int      `json:"max_age_seconds,omitempty"`
}

type SecurityAlertPolicy struct {
	RiskLevels []string `json:"risk_levels,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
}

type AdaptiveSecurityPolicy struct {
	MFA     MFAPolicy                     `json:"mfa"`
	Risk    RiskPolicy                    `json:"risk"`
	Actions map[string]StepUpActionPolicy `json:"actions,omitempty"`
	Alerts  SecurityAlertPolicy           `json:"alerts,omitempty"`
}

type RiskSignal struct {
	Type     string                 `json:"type"`
	Level    string                 `json:"level"`
	Reason   string                 `json:"reason,omitempty"`
	Metadata map[string]interface{} `json:"metadata,omitempty"`
}

type RiskAssessment struct {
	Level   string                 `json:"level"`
	Score   int                    `json:"score"`
	Signals []RiskSignal           `json:"signals,omitempty"`
	Context map[string]interface{} `json:"context,omitempty"`
}

type UserDevice struct {
	ID             string                 `json:"id"`
	ClientID       string                 `json:"client_id"`
	UserID         string                 `json:"user_id"`
	Fingerprint    string                 `json:"fingerprint"`
	Name           string                 `json:"name"`
	UserAgent      string                 `json:"user_agent"`
	IPAddress      string                 `json:"ip_address"`
	Trusted        bool                   `json:"trusted"`
	Remembered     bool                   `json:"remembered"`
	TrustExpiresAt *time.Time             `json:"trust_expires_at,omitempty"`
	LastSeenAt     time.Time              `json:"last_seen_at"`
	Metadata       map[string]interface{} `json:"metadata"`
	CreatedAt      time.Time              `json:"created_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
}
