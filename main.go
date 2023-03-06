package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"runtime"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	_ "go.uber.org/automaxprocs"
	"gomodules.xyz/logs"
	"gomodules.xyz/signals"
	v "gomodules.xyz/x/version"
	"k8s.io/klog/v2"
)

var (
	version = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "version",
		Help: "Version information about this binary",
		ConstLabels: map[string]string{
			"version": v.Version.Version,
		},
	})

	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "http_requests_total",
		Help: "Count of all HTTP requests",
	}, []string{"code", "method"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "http_request_duration_seconds",
		Help: "Duration of all HTTP requests",
	}, []string{"code", "method"})
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		return new(bytes.Buffer)
	},
}

func main() {
	rootCmd := NewRootCmd()
	logs.Init(rootCmd, true)
	defer logs.FlushLogs()

	if len(os.Getenv("GOMAXPROCS")) == 0 {
		runtime.GOMAXPROCS(runtime.NumCPU())
	}

	if err := rootCmd.Execute(); err != nil {
		klog.Fatalln("Error in scanner Main:", err)
	}
}

func NewRootCmd() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:               "cloudflare-dns-proxy [command]",
		Short:             `Cloudflare DNS Proxy by AppsCode`,
		DisableAutoGenTag: true,
	}

	rootCmd.AddCommand(v.NewCmdVersion())
	ctx := signals.SetupSignalContext()
	rootCmd.AddCommand(NewCmdRun(ctx))

	return rootCmd
}

func NewCmdRun(ctx context.Context) *cobra.Command {
	var (
		addr             = ":8000"
		metricsAddr      = ":8080"
		apiServerAddress = ""
		debug            = false
	)
	cmd := &cobra.Command{
		Use:               "run",
		Short:             "Launch a Cloudflare DNS Proxy server",
		Long:              "Launch a Cloudflare DNS Proxy server",
		DisableAutoGenTag: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			klog.Infof("Starting binary version %s+%s ...", v.Version.Version, v.Version.CommitHash)

			return run(ctx, addr, metricsAddr, apiServerAddress, debug)
		},
	}
	cmd.Flags().StringVar(&addr, "listen", addr, "Listen address.")
	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", metricsAddr, "The address the metric endpoint binds to.")
	cmd.Flags().StringVar(&apiServerAddress, "api-server-addr", apiServerAddress, "The API server address")
	cmd.Flags().BoolVar(&debug, "debug", debug, "If true, dumps proxied request and responses")

	return cmd
}

func run(ctx context.Context, addr, metricsAddr, apiServerAddress string, debug bool) error {
	target, err := url.Parse("https://google.com")
	if err != nil {
		return err
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = cloudflareTransport{
		debug: debug,
	}

	r := prometheus.NewRegistry()
	r.MustRegister(httpRequestsTotal)
	r.MustRegister(httpRequestDuration)
	r.MustRegister(version)

	router := chi.NewRouter()
	// router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.HandleFunc("/*", promhttp.InstrumentHandlerDuration(
		httpRequestDuration,
		promhttp.InstrumentHandlerCounter(httpRequestsTotal, proxy),
	))
	srv := http.Server{
		Addr:    addr,
		Handler: router,
	}
	go func() {
		log.Printf("API server listening at http://%s", addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "HTTP server ListenAndServe failed")
		}
	}()

	go func() {
		mux := http.NewServeMux()
		mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("OK"))
		}))
		mux.Handle("/metrics", promhttp.HandlerFor(r, promhttp.HandlerOpts{}))
		metricsServer := http.Server{
			Addr:    metricsAddr,
			Handler: mux,
		}
		log.Printf("Telemetry server listening at http://%s", metricsAddr)
		if err := metricsServer.ListenAndServe(); err != http.ErrServerClosed {
			klog.ErrorS(err, "Metrics server ListenAndServe failed")
		}
	}()

	<-ctx.Done()
	return srv.Shutdown(ctx)
}

type cloudflareTransport struct {
	debug bool
}

func (rt cloudflareTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if rt.debug {
		if data, err := httputil.DumpRequestOut(req, true); err == nil {
			fmt.Println("REQUEST: >>>>>>>>>>>>>>>>>>>>>>>")
			fmt.Println(string(data))
		}
	}

	req.Host = ""
	// req.Header.Set("Authorization", "Bearer "+rt.apiToken)

	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if rt.debug {
		if data, err := httputil.DumpResponse(resp, false); err == nil {
			fmt.Println("RESPONSE: >>>>>>>>>>>>>>>>>>>>>>>")
			fmt.Println(string(data))
		}
	}
	return resp, nil
}
