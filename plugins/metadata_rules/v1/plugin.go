package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"text/template"

	prommodel "github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/model/rulefmt"
	"github.com/slok/sloth/pkg/common/conventions"
	"github.com/slok/sloth/pkg/common/model"
	utilsdata "github.com/slok/sloth/pkg/common/utils/data"
	promutils "github.com/slok/sloth/pkg/common/utils/prometheus"
	pluginslov1 "github.com/slok/sloth/pkg/prometheus/plugin/slo/v1"
)

const (
	PluginVersion = "prometheus/slo/v1"
	PluginID      = "mongodb.org/core_mod/metadata_rules/v1"
)

type Config struct {
	GroupByLabels []string `json:"groupByLabels,omitempty"`
}

func NewPlugin(configData json.RawMessage, _ pluginslov1.AppUtils) (pluginslov1.Plugin, error) {
	config := Config{}
	err := json.Unmarshal(configData, &config)
	if err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return plugin{config: config}, nil
}

type plugin struct {
	config Config
}

func (p plugin) ProcessSLO(ctx context.Context, request *pluginslov1.Request, result *pluginslov1.Result) error {
	metadataRules, err := p.generateMetadataRecordingRules(ctx, request.Info, request.SLO, request.MWMBAlertGroup)
	if err != nil {
		return err
	}
	result.SLORules.MetadataRecRules.Rules = metadataRules
	return nil
}

func (p plugin) generateMetadataRecordingRules(ctx context.Context, info model.Info, slo model.PromSLO, alerts model.MWMBAlertGroup) ([]rulefmt.Rule, error) {
	labels := utilsdata.MergeLabels(conventions.GetSLOIDPromLabels(slo), slo.Labels)

	// Metatada Recordings.
	const (
		metricSLOCurrentBurnRateRatio            = "slo:current_burn_rate:ratio"
		metricSLOPeriodBurnRateRatio             = "slo:period_burn_rate:ratio"
		metricSLOPeriodErrorBudgetRemainingRatio = "slo:period_error_budget_remaining:ratio"
		metricSLOInfo                            = "sloth_slo_info"
		metricSLOObjectiveRatio                  = "slo:objective:ratio"
		metricSLOErrorBudgetRatio                = "slo:error_budget:ratio"
		metricSLOTimePeriodDays                  = "slo:time_period:days"
	)

	sloObjectiveRatio := slo.Objective / 100

	sloFilter := promutils.LabelsToPromFilter(labels)

	// allow us to group by labels we don't filter on (eg. exported region differs from metric region)
	groupLabels := make(map[string]string, len(p.config.GroupByLabels))
	for _, label := range p.config.GroupByLabels {
		if _, ok := labels[label]; !ok {
			groupLabels[label] = ""
		}
	}
	sloGroup := labelsToPromGroup(utilsdata.MergeLabels(groupLabels, labels))

	var currentBurnRateExpr bytes.Buffer
	err := burnRateRecordingExprTpl.Execute(&currentBurnRateExpr, map[string]string{
		"SLIErrorMetric":         conventions.GetSLIErrorMetric(alerts.PageQuick.ShortWindow),
		"MetricFilter":           sloFilter,
		"SLOGroup":               sloGroup,
		"ErrorBudgetRatioMetric": metricSLOErrorBudgetRatio,
	})
	if err != nil {
		return nil, fmt.Errorf("could not render current burn rate prometheus metadata recording rule expression: %w", err)
	}

	var periodBurnRateExpr bytes.Buffer
	err = burnRateRecordingExprTpl.Execute(&periodBurnRateExpr, map[string]string{
		"SLIErrorMetric":         conventions.GetSLIErrorMetric(slo.TimeWindow),
		"MetricFilter":           sloFilter,
		"SLOGroup":               sloGroup,
		"ErrorBudgetRatioMetric": metricSLOErrorBudgetRatio,
	})
	if err != nil {
		return nil, fmt.Errorf("could not render period burn rate prometheus metadata recording rule expression: %w", err)
	}

	burnRateGroupLeft := ""
	infoGroupLeft := ""

	if len(groupLabels) > 0 {
		sloMinimalGroup := labelsToPromGroup(groupLabels)

		// We must derive the group labels from the prior burn rate rule and group left to the vectors below
		var currentBurnRateLabels bytes.Buffer
		err = labelGroupRecordingExprTpl.Execute(&currentBurnRateLabels, map[string]string{
			"BurnRateMetric": metricSLOCurrentBurnRateRatio,
			"MetricFilter":   sloFilter,
			"SLOGroup":       sloMinimalGroup,
		})
		if err != nil {
			return nil, fmt.Errorf("could not render group labels from current burn rate for prometheus metadata recording rule expression: %w", err)
		}
		burnRateGroupLeft = currentBurnRateLabels.String()

		// Makes slightly more sense to use the info label where we have it
		var infoLabels bytes.Buffer
		err = labelGroupRecordingExprTpl.Execute(&infoLabels, map[string]string{
			"BurnRateMetric": metricSLOInfo,
			"MetricFilter":   sloFilter,
			"SLOGroup":       sloMinimalGroup,
		})
		if err != nil {
			return nil, fmt.Errorf("could not render group labels from slo info metric for prometheus metadata recording rule expression: %w", err)
		}
		infoGroupLeft = infoLabels.String()
	}

	// Order for group labels. Burn rate and info come first so we can use them later to get label values
	rules := []rulefmt.Rule{
		// Current burning speed.
		{
			Record: metricSLOCurrentBurnRateRatio,
			Expr:   currentBurnRateExpr.String(),
			Labels: labels,
		},

		// Total period burn rate.
		{
			Record: metricSLOPeriodBurnRateRatio,
			Expr:   periodBurnRateExpr.String(),
			Labels: labels,
		},

		// Total Error budget remaining period.
		{
			Record: metricSLOPeriodErrorBudgetRemainingRatio,
			Expr:   fmt.Sprintf(`1 - %s%s`, metricSLOPeriodBurnRateRatio, sloFilter),
			Labels: labels,
		},

		// Info.
		{
			Record: metricSLOInfo,
			Expr:   fmt.Sprintf(`vector(1)%s`, burnRateGroupLeft),
			Labels: utilsdata.MergeLabels(labels, map[string]string{
				conventions.PromSLOVersionLabelName:   info.Version,
				conventions.PromSLOModeLabelName:      string(info.Mode),
				conventions.PromSLOSpecLabelName:      info.Spec,
				conventions.PromSLOObjectiveLabelName: strconv.FormatFloat(slo.Objective, 'f', -1, 64),
			}),
		},

		// SLO Objective.
		{
			Record: metricSLOObjectiveRatio,
			Expr:   fmt.Sprintf(`vector(%g)%s`, sloObjectiveRatio, infoGroupLeft),
			Labels: labels,
		},

		// Error budget.
		{
			Record: metricSLOErrorBudgetRatio,
			Expr:   fmt.Sprintf(`vector(1-%g)%s`, sloObjectiveRatio, infoGroupLeft),
			Labels: labels,
		},

		// Total period.
		{
			Record: metricSLOTimePeriodDays,
			Expr:   fmt.Sprintf(`vector(%g)%s`, slo.TimeWindow.Hours()/24, infoGroupLeft),
			Labels: labels,
		},
	}

	// If not grouping, reorder to the original order to avoid PrometheusRule resource churn
	if len(groupLabels) == 0 {
		origRules := []rulefmt.Rule{rules[4], rules[5], rules[6], rules[0], rules[1], rules[2], rules[3]}
		rules = origRules
	}

	return rules, nil
}

// labelsToPromGroup converts a map of labels to a Prometheus filter string.
func labelsToPromGroup(labels map[string]string) string {
	metricGroup := prommodel.LabelNames{}
	for k, _ := range labels {
		metricGroup = append(metricGroup, prommodel.LabelName(k))
	}

	sort.Sort(metricGroup)
	return metricGroup.String()
}

var burnRateRecordingExprTpl = template.Must(template.New("burnRateExpr").Option("missingkey=error").Parse(`{{ .SLIErrorMetric }}{{ .MetricFilter }}
/ on({{ .SLOGroup }}) group_left
{{ .ErrorBudgetRatioMetric }}{{ .MetricFilter }}
`))

var labelGroupRecordingExprTpl = template.Must(template.New("labelGroupExpr").Option("missingkey=error").Parse(` * group({{ .BurnRateMetric }}{{ .MetricFilter }})
by ({{ .SLOGroup }})`))
