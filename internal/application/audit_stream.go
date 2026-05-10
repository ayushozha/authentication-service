package application

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type AuditLogStreamConfig struct {
	Providers []string
	Timeout   time.Duration
	Attempts  int
	Service   string
	Env       string

	DatadogURL    string
	DatadogAPIKey string

	SplunkHECURL   string
	SplunkHECToken string

	ElasticBulkURL string
	ElasticAPIKey  string
	ElasticIndex   string

	AWSRegion           string
	AWSAccessKeyID      string
	AWSSecretAccessKey  string
	AWSSessionToken     string
	S3Bucket            string
	S3Prefix            string
	CloudWatchLogGroup  string
	CloudWatchLogStream string

	GCPProjectID   string
	GCPLogID       string
	GCPAccessToken string
	GCPLoggingURL  string

	AzureMonitorURL         string
	AzureMonitorBearerToken string
}

type auditLogStream struct {
	targets  []auditLogStreamTarget
	timeout  time.Duration
	attempts int
	client   *http.Client
}

type auditLogStreamTarget struct {
	name string
	send func(context.Context, *domain.AuditEvent, []byte) error
}

func NewAuditLogStream(cfg AuditLogStreamConfig) domain.AuditEventSink {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.Attempts <= 0 {
		cfg.Attempts = 3
	}
	if cfg.Service == "" {
		cfg.Service = "authservice"
	}
	stream := &auditLogStream{
		timeout:  cfg.Timeout,
		attempts: cfg.Attempts,
		client:   &http.Client{Timeout: cfg.Timeout},
	}
	for _, provider := range cfg.Providers {
		switch strings.ToLower(strings.TrimSpace(provider)) {
		case "":
			continue
		case "stdout", "console":
			stream.targets = append(stream.targets, stream.stdoutTarget())
		case "datadog":
			if cfg.DatadogAPIKey == "" {
				log.Printf("audit stream datadog disabled: DATADOG_API_KEY is not set")
				continue
			}
			if cfg.DatadogURL == "" {
				cfg.DatadogURL = "https://http-intake.logs.datadoghq.com/v1/input"
			}
			stream.targets = append(stream.targets, stream.datadogTarget(cfg))
		case "splunk":
			if cfg.SplunkHECURL == "" || cfg.SplunkHECToken == "" {
				log.Printf("audit stream splunk disabled: SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN are required")
				continue
			}
			stream.targets = append(stream.targets, stream.splunkTarget(cfg))
		case "elastic", "elasticsearch":
			if cfg.ElasticBulkURL == "" || cfg.ElasticIndex == "" {
				log.Printf("audit stream elastic disabled: ELASTIC_BULK_URL and ELASTIC_INDEX are required")
				continue
			}
			stream.targets = append(stream.targets, stream.elasticTarget(cfg))
		case "s3":
			if !cfg.hasAWSCredentials() || cfg.S3Bucket == "" || cfg.AWSRegion == "" {
				log.Printf("audit stream s3 disabled: AWS credentials, AWS_REGION, and AUDIT_S3_BUCKET are required")
				continue
			}
			stream.targets = append(stream.targets, stream.s3Target(cfg))
		case "cloudwatch":
			if !cfg.hasAWSCredentials() || cfg.CloudWatchLogGroup == "" || cfg.CloudWatchLogStream == "" || cfg.AWSRegion == "" {
				log.Printf("audit stream cloudwatch disabled: AWS credentials, AWS_REGION, AUDIT_CLOUDWATCH_LOG_GROUP, and AUDIT_CLOUDWATCH_LOG_STREAM are required")
				continue
			}
			stream.targets = append(stream.targets, stream.cloudWatchTarget(cfg))
		case "gcp", "google", "google-cloud-logging":
			if cfg.GCPProjectID == "" || cfg.GCPAccessToken == "" {
				log.Printf("audit stream gcp disabled: GCP_PROJECT_ID and GCP_ACCESS_TOKEN are required")
				continue
			}
			if cfg.GCPLogID == "" {
				cfg.GCPLogID = "authservice-audit"
			}
			if cfg.GCPLoggingURL == "" {
				cfg.GCPLoggingURL = "https://logging.googleapis.com/v2/entries:write"
			}
			stream.targets = append(stream.targets, stream.gcpTarget(cfg))
		case "azure", "azure-monitor":
			if cfg.AzureMonitorURL == "" || cfg.AzureMonitorBearerToken == "" {
				log.Printf("audit stream azure disabled: AZURE_MONITOR_INGEST_URL and AZURE_MONITOR_BEARER_TOKEN are required")
				continue
			}
			stream.targets = append(stream.targets, stream.azureTarget(cfg))
		default:
			log.Printf("audit stream provider %q is not supported", provider)
		}
	}
	if len(stream.targets) == 0 {
		return nil
	}
	return stream
}

func (cfg AuditLogStreamConfig) hasAWSCredentials() bool {
	return cfg.AWSAccessKeyID != "" && cfg.AWSSecretAccessKey != ""
}

func (s *auditLogStream) PublishAuditEvent(ctx context.Context, event *domain.AuditEvent) {
	if s == nil || event == nil {
		return
	}
	payload, err := json.Marshal(auditStreamEnvelope(event))
	if err != nil {
		return
	}
	for _, target := range s.targets {
		target := target
		for attempt := 1; attempt <= s.attempts; attempt++ {
			reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
			err := target.send(reqCtx, event, payload)
			cancel()
			if err == nil {
				Metrics().Inc("authservice_audit_stream_delivery_total", map[string]string{"provider": target.name, "result": "success"}, 1)
				break
			}
			if attempt == s.attempts {
				Metrics().Inc("authservice_audit_stream_delivery_total", map[string]string{"provider": target.name, "result": "failure"}, 1)
				log.Printf("audit stream %s delivery failed: %v", target.name, err)
				break
			}
			time.Sleep(time.Duration(attempt) * 200 * time.Millisecond)
		}
	}
}

func (s *auditLogStream) stdoutTarget() auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "stdout",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			log.Printf("audit_stream=%s", string(payload))
			return nil
		},
	}
}

func (s *auditLogStream) datadogTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "datadog",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			headers := map[string]string{
				"Content-Type": "application/json",
				"DD-API-KEY":   cfg.DatadogAPIKey,
			}
			return s.post(ctx, cfg.DatadogURL, headers, payload)
		},
	}
}

func (s *auditLogStream) splunkTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "splunk",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			var body bytes.Buffer
			_ = json.NewEncoder(&body).Encode(map[string]interface{}{
				"time":       float64(event.CreatedAt.UnixNano()) / float64(time.Second),
				"source":     "authservice",
				"sourcetype": "_json",
				"event":      json.RawMessage(payload),
			})
			headers := map[string]string{
				"Authorization": "Splunk " + cfg.SplunkHECToken,
				"Content-Type":  "application/json",
			}
			return s.post(ctx, cfg.SplunkHECURL, headers, body.Bytes())
		},
	}
}

func (s *auditLogStream) elasticTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "elastic",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			docID := strconv.FormatInt(event.ID, 10)
			if event.EventHash != "" {
				docID = event.EventHash
			}
			action, _ := json.Marshal(map[string]interface{}{"index": map[string]string{"_index": cfg.ElasticIndex, "_id": docID}})
			body := append(append(action, '\n'), payload...)
			body = append(body, '\n')
			headers := map[string]string{"Content-Type": "application/x-ndjson"}
			if cfg.ElasticAPIKey != "" {
				headers["Authorization"] = "ApiKey " + cfg.ElasticAPIKey
			}
			return s.post(ctx, cfg.ElasticBulkURL, headers, body)
		},
	}
}

func (s *auditLogStream) s3Target(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "s3",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			key := s3AuditObjectKey(cfg.S3Prefix, event)
			endpoint := "https://" + cfg.S3Bucket + ".s3." + cfg.AWSRegion + ".amazonaws.com/" + key
			body := append(append([]byte(nil), payload...), '\n')
			req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/x-ndjson")
			signAWSRequest(req, cfg.AWSRegion, "s3", cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSSessionToken, body, time.Now().UTC())
			return s.do(req)
		},
	}
}

func (s *auditLogStream) cloudWatchTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "cloudwatch",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			body, _ := json.Marshal(map[string]interface{}{
				"logGroupName":  cfg.CloudWatchLogGroup,
				"logStreamName": cfg.CloudWatchLogStream,
				"logEvents": []map[string]interface{}{
					{
						"timestamp": event.CreatedAt.UnixMilli(),
						"message":   string(payload),
					},
				},
			})
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://logs."+cfg.AWSRegion+".amazonaws.com/", bytes.NewReader(body))
			if err != nil {
				return err
			}
			req.Header.Set("Content-Type", "application/x-amz-json-1.1")
			req.Header.Set("X-Amz-Target", "Logs_20140328.PutLogEvents")
			signAWSRequest(req, cfg.AWSRegion, "logs", cfg.AWSAccessKeyID, cfg.AWSSecretAccessKey, cfg.AWSSessionToken, body, time.Now().UTC())
			return s.do(req)
		},
	}
}

func (s *auditLogStream) gcpTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "gcp",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			var envelope map[string]interface{}
			_ = json.Unmarshal(payload, &envelope)
			body, _ := json.Marshal(map[string]interface{}{
				"logName": "projects/" + cfg.GCPProjectID + "/logs/" + url.PathEscape(cfg.GCPLogID),
				"resource": map[string]string{
					"type": "global",
				},
				"entries": []map[string]interface{}{
					{
						"timestamp":   event.CreatedAt.Format(time.RFC3339Nano),
						"jsonPayload": envelope,
					},
				},
			})
			headers := map[string]string{
				"Authorization": "Bearer " + cfg.GCPAccessToken,
				"Content-Type":  "application/json",
			}
			return s.post(ctx, cfg.GCPLoggingURL, headers, body)
		},
	}
}

func (s *auditLogStream) azureTarget(cfg AuditLogStreamConfig) auditLogStreamTarget {
	return auditLogStreamTarget{
		name: "azure",
		send: func(ctx context.Context, event *domain.AuditEvent, payload []byte) error {
			body := append(append([]byte{'['}, payload...), ']')
			headers := map[string]string{
				"Authorization": "Bearer " + cfg.AzureMonitorBearerToken,
				"Content-Type":  "application/json",
			}
			return s.post(ctx, cfg.AzureMonitorURL, headers, body)
		},
	}
}

func (s *auditLogStream) post(ctx context.Context, endpoint string, headers map[string]string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	return s.do(req)
}

func (s *auditLogStream) do(req *http.Request) error {
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("provider returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func auditStreamEnvelope(event *domain.AuditEvent) map[string]interface{} {
	return map[string]interface{}{
		"service":         "authservice",
		"event_id":        event.ID,
		"client_id":       event.ClientID,
		"user_id":         event.UserID,
		"event_type":      event.EventType,
		"actor_type":      event.ActorType,
		"actor_id":        event.ActorID,
		"actor_email":     event.ActorEmail,
		"target_type":     event.TargetType,
		"target_id":       event.TargetID,
		"request_id":      event.RequestID,
		"ip_address":      event.IPAddress,
		"user_agent":      event.UserAgent,
		"metadata":        event.Metadata,
		"before_metadata": event.BeforeMetadata,
		"after_metadata":  event.AfterMetadata,
		"created_at":      event.CreatedAt,
		"retention_until": event.RetentionUntil,
		"legal_hold":      event.LegalHold,
		"chain_scope":     event.ChainScope,
		"previous_hash":   event.PreviousHash,
		"event_hash":      event.EventHash,
		"hash_algorithm":  event.HashAlgorithm,
	}
}

func s3AuditObjectKey(prefix string, event *domain.AuditEvent) string {
	created := event.CreatedAt.UTC()
	hash := event.EventHash
	if hash == "" {
		hash = strconv.FormatInt(event.ID, 10)
	}
	parts := strings.Split(strings.Trim(strings.TrimSpace(prefix), "/"), "/")
	parts = append(parts,
		created.Format("2006"),
		created.Format("01"),
		created.Format("02"),
		strconv.FormatInt(event.ID, 10)+"-"+hash+".ndjson",
	)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if part != "" {
			out = append(out, url.PathEscape(part))
		}
	}
	return strings.Join(out, "/")
}

func signAWSRequest(req *http.Request, region, service, accessKey, secretKey, sessionToken string, body []byte, now time.Time) {
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	payloadHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", sessionToken)
	}

	canonicalHeaders, signedHeaders := canonicalAWSHeaders(req)
	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalAWSPath(req.URL),
		req.URL.Query().Encode(),
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")
	scope := strings.Join([]string{date, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		scope,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")
	signature := hex.EncodeToString(hmacSHA256(awsSigningKey(secretKey, date, region, service), []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+accessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

func canonicalAWSHeaders(req *http.Request) (string, string) {
	headers := map[string]string{"host": req.URL.Host}
	for key, values := range req.Header {
		lower := strings.ToLower(key)
		cleaned := make([]string, 0, len(values))
		for _, value := range values {
			cleaned = append(cleaned, strings.Join(strings.Fields(value), " "))
		}
		headers[lower] = strings.Join(cleaned, ",")
	}
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for _, key := range keys {
		canonical.WriteString(key)
		canonical.WriteByte(':')
		canonical.WriteString(strings.TrimSpace(headers[key]))
		canonical.WriteByte('\n')
	}
	return canonical.String(), strings.Join(keys, ";")
}

func canonicalAWSPath(u *url.URL) string {
	path := u.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

func awsSigningKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), []byte(date))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	return hmacSHA256(kService, []byte("aws4_request"))
}

func hmacSHA256(key, value []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(value)
	return mac.Sum(nil)
}

func sha256Hex(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
