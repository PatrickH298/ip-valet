package web

import (
	"errors"
	"fmt"
	"net/http"
	"sort"

	"github.com/PatrickH298/ip-valet/dashboard/internal/api"
)

type overviewView struct {
	Ready      bool
	ReadyError string
	Health     *api.Health
	HealthErr  string
	Workers    []workerRow
	Attention  int // workers that need a look
	SelfKeyID  string
}

type workerRow struct {
	Health      api.WorkerHealth
	Status      string
	StatusClass string
}

// workerStatus sums up a worker's health in a few words.
func workerStatus(h api.WorkerHealth) (string, string) {
	switch {
	case h.LastSeenAt == nil:
		return "never reported", "warn"
	case h.LastErrorAt != nil && !h.LastErrorAt.Before(*h.LastSeenAt):
		return "failing", "bad"
	case h.Lag > 0:
		return fmt.Sprintf("%d behind", h.Lag), "warn"
	case len(h.Rejections) > 0:
		return plural(len(h.Rejections), "rejection", "rejections"), "warn"
	}
	return "up to date", "ok"
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) error {
	v := overviewView{SelfKeyID: s.SelfKeyID}
	if err := s.API.Ready(r.Context()); err != nil {
		v.ReadyError = err.Error()
	} else {
		v.Ready = true
	}
	h, err := s.API.Health(r.Context())
	var ae *api.Error
	switch {
	case err == nil:
		v.Health = &h
		for _, wh := range h.Workers {
			st, cls := workerStatus(wh)
			if cls != "ok" {
				v.Attention++
			}
			v.Workers = append(v.Workers, workerRow{Health: wh, Status: st, StatusClass: cls})
		}
		// Workers needing a look first, then by name.
		sort.SliceStable(v.Workers, func(i, j int) bool {
			return rank(v.Workers[i].StatusClass) < rank(v.Workers[j].StatusClass)
		})
	case errors.As(err, &ae) && (ae.Status == 0 || ae.Status == http.StatusServiceUnavailable):
		v.HealthErr = "Worker health is unavailable: " + err.Error()
	default:
		return err
	}
	s.render(w, r, http.StatusOK, "overview", "Overview", "overview", v)
	return nil
}

func rank(class string) int {
	switch class {
	case "bad":
		return 0
	case "warn":
		return 1
	}
	return 2
}
