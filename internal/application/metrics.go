package application

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Ayush10/authentication-service/internal/domain"
)

type metricKey struct {
	name   string
	labels string
}

type metricSummary struct {
	count uint64
	sum   float64
}

type MetricsRegistry struct {
	mu        sync.RWMutex
	counters  map[metricKey]float64
	gauges    map[metricKey]float64
	summaries map[metricKey]metricSummary
}

func NewMetricsRegistry() *MetricsRegistry {
	return &MetricsRegistry{
		counters:  map[metricKey]float64{},
		gauges:    map[metricKey]float64{},
		summaries: map[metricKey]metricSummary{},
	}
}

var (
	defaultMetricsMu sync.RWMutex
	defaultMetrics   = NewMetricsRegistry()
)

func SetMetricsRegistry(registry *MetricsRegistry) {
	if registry == nil {
		registry = NewMetricsRegistry()
	}
	defaultMetricsMu.Lock()
	defer defaultMetricsMu.Unlock()
	defaultMetrics = registry
}

func Metrics() *MetricsRegistry {
	defaultMetricsMu.RLock()
	defer defaultMetricsMu.RUnlock()
	return defaultMetrics
}

func (m *MetricsRegistry) Inc(name string, labels map[string]string, delta float64) {
	if m == nil || delta == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := metricKey{name: name, labels: encodeMetricLabels(labels)}
	m.counters[key] += delta
}

func (m *MetricsRegistry) SetGauge(name string, labels map[string]string, value float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := metricKey{name: name, labels: encodeMetricLabels(labels)}
	m.gauges[key] = value
}

func (m *MetricsRegistry) ObserveSummary(name string, labels map[string]string, value float64) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	key := metricKey{name: name, labels: encodeMetricLabels(labels)}
	summary := m.summaries[key]
	summary.count++
	summary.sum += value
	m.summaries[key] = summary
}

func (m *MetricsRegistry) ObserveAuditEvent(event *domain.AuditEvent) {
	if m == nil || event == nil {
		return
	}
	labels := map[string]string{"client_id": event.ClientID}
	switch event.EventType {
	case "login_success":
		labels["result"] = "success"
		m.Inc("authservice_login_total", labels, 1)
	case "login_failed", "login_locked", "login_blocked":
		labels["result"] = "failure"
		labels["reason"] = event.EventType
		m.Inc("authservice_login_total", labels, 1)
	case "adaptive_mfa_challenge":
		m.Inc("authservice_mfa_challenge_total", map[string]string{
			"client_id": event.ClientID,
			"method":    metricString(event.Metadata["method"], "totp"),
		}, 1)
	case "token_refresh_reuse":
		m.Inc("authservice_token_refresh_reuse_total", labels, 1)
	}
}

func (m *MetricsRegistry) ObserveHTTP(method, path string, status int, latency time.Duration) {
	if m == nil {
		return
	}
	labels := map[string]string{
		"method": method,
		"path":   normalizeMetricPath(path),
		"status": strconv.Itoa(status),
	}
	m.Inc("authservice_http_requests_total", labels, 1)
	m.ObserveSummary("authservice_http_request_latency_seconds", labels, latency.Seconds())
}

func (m *MetricsRegistry) ObserveSSOError(stage string, err error) {
	if m == nil || err == nil {
		return
	}
	m.Inc("authservice_sso_errors_total", map[string]string{
		"stage":  metricLabelValue(stage),
		"reason": metricLabelValue(err.Error()),
	}, 1)
}

func (m *MetricsRegistry) ObserveSCIMSyncLag(clientID, directoryID string, lag time.Duration) {
	if m == nil {
		return
	}
	if lag < 0 {
		lag = 0
	}
	labels := map[string]string{
		"client_id":    clientID,
		"directory_id": directoryID,
	}
	m.SetGauge("authservice_scim_sync_lag_seconds", labels, lag.Seconds())
	m.Inc("authservice_scim_sync_events_total", labels, 1)
}

func (m *MetricsRegistry) ObserveWebhookDelivery(result string, latency time.Duration) {
	if m == nil {
		return
	}
	labels := map[string]string{"result": metricLabelValue(result)}
	m.Inc("authservice_webhook_delivery_total", labels, 1)
	m.ObserveSummary("authservice_webhook_delivery_latency_seconds", labels, latency.Seconds())
}

func (m *MetricsRegistry) ObserveTokenRefreshReuse(clientID string) {
	if m == nil {
		return
	}
	m.Inc("authservice_token_refresh_reuse_total", map[string]string{"client_id": clientID}, 1)
}

func (m *MetricsRegistry) WritePrometheus(w http.ResponseWriter) {
	if m == nil {
		m = NewMetricsRegistry()
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write(m.PrometheusText())
}

func (m *MetricsRegistry) PrometheusText() []byte {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var buf bytes.Buffer
	writeMetricFamilies(&buf, "counter", m.counters)
	writeMetricFamilies(&buf, "gauge", m.gauges)

	summaryKeys := make([]metricKey, 0, len(m.summaries))
	for key := range m.summaries {
		summaryKeys = append(summaryKeys, key)
	}
	sortMetricKeys(summaryKeys)
	for _, key := range summaryKeys {
		summary := m.summaries[key]
		writePrometheusSample(&buf, key.name+"_sum", key.labels, summary.sum)
		writePrometheusSample(&buf, key.name+"_count", key.labels, float64(summary.count))
	}
	return buf.Bytes()
}

type MetricsAuditSink struct {
	registry *MetricsRegistry
}

func NewMetricsAuditSink(registry *MetricsRegistry) *MetricsAuditSink {
	return &MetricsAuditSink{registry: registry}
}

func (s *MetricsAuditSink) PublishAuditEvent(ctx context.Context, event *domain.AuditEvent) {
	if s == nil {
		return
	}
	registry := s.registry
	if registry == nil {
		registry = Metrics()
	}
	registry.ObserveAuditEvent(event)
}

type CompositeAuditEventSink struct {
	sinks []domain.AuditEventSink
}

func NewCompositeAuditEventSink(sinks ...domain.AuditEventSink) domain.AuditEventSink {
	filtered := make([]domain.AuditEventSink, 0, len(sinks))
	for _, sink := range sinks {
		if sink != nil {
			filtered = append(filtered, sink)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	return &CompositeAuditEventSink{sinks: filtered}
}

func (s *CompositeAuditEventSink) PublishAuditEvent(ctx context.Context, event *domain.AuditEvent) {
	if s == nil {
		return
	}
	for _, sink := range s.sinks {
		sink.PublishAuditEvent(ctx, event)
	}
}

func encodeMetricLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+metricLabelValue(labels[key]))
	}
	return strings.Join(parts, ",")
}

func writeMetricFamilies(buf *bytes.Buffer, metricType string, metrics map[metricKey]float64) {
	keys := make([]metricKey, 0, len(metrics))
	for key := range metrics {
		keys = append(keys, key)
	}
	sortMetricKeys(keys)
	for _, key := range keys {
		writePrometheusSample(buf, key.name, key.labels, metrics[key])
	}
}

func writePrometheusSample(buf *bytes.Buffer, name, labels string, value float64) {
	if labels == "" {
		_, _ = fmt.Fprintf(buf, "%s %g\n", name, value)
		return
	}
	_, _ = fmt.Fprintf(buf, "%s{%s} %g\n", name, prometheusLabels(labels), value)
}

func prometheusLabels(encoded string) string {
	if encoded == "" {
		return ""
	}
	parts := strings.Split(encoded, ",")
	for i, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		parts[i] = key + `="` + strings.ReplaceAll(value, `"`, `\"`) + `"`
	}
	return strings.Join(parts, ",")
}

func sortMetricKeys(keys []metricKey) {
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name == keys[j].name {
			return keys[i].labels < keys[j].labels
		}
		return keys[i].name < keys[j].name
	})
}

func metricString(value interface{}, fallback string) string {
	if raw, ok := value.(string); ok && strings.TrimSpace(raw) != "" {
		return raw
	}
	return fallback
}

func metricLabelValue(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	if value == "" {
		return "unknown"
	}
	replacer := strings.NewReplacer(" ", "_", "/", "_", ":", "_", ",", "_", "=", "_", `"`, "", "\n", "_", "\r", "_")
	value = replacer.Replace(value)
	if len(value) > 80 {
		return value[:80]
	}
	return value
}

func normalizeMetricPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if strings.HasPrefix(path, "/api/admin/clients/") {
		return "/api/admin/clients/:client_id"
	}
	if strings.HasPrefix(path, "/api/auth/sso/callback/") {
		return "/api/auth/sso/callback/:connection_id"
	}
	if strings.HasPrefix(path, "/api/auth/sso/metadata/") {
		return "/api/auth/sso/metadata/:connection_id"
	}
	if strings.HasPrefix(path, "/api/auth/sso/") {
		return "/api/auth/sso/:connection_id"
	}
	if strings.HasPrefix(path, "/scim/v2/") {
		return "/scim/v2/:directory_id/:resource"
	}
	return path
}
