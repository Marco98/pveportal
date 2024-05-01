package proxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/Marco98/pveportal/pkg/config"
)

type listClustersCluster struct {
	Name      string `json:"name"`
	SwitchURL string `json:"switch_url"`
}

func listClusters(cc []config.Cluster) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		currentClusterEnc, err := r.Cookie(clusterCookieName)
		if err != nil {
			return
		}
		currentCluster, err := url.QueryUnescape(currentClusterEnc.Value)
		if err != nil {
			return
		}
		clusters := make([]listClustersCluster, 0)
		for _, v := range cc {
			if v.Name == currentCluster {
				continue
			}
			clusters = append(clusters, listClustersCluster{
				Name:      v.Name,
				SwitchURL: fmt.Sprintf("%sapi/switchcluster?name=%s", localHTTPDir, url.QueryEscape(v.Name)),
			})
		}
		respb, err := json.Marshal(struct {
			CurrentCluster string                `json:"current_cluster"`
			Clusters       []listClustersCluster `json:"clusters"`
		}{
			CurrentCluster: currentCluster,
			Clusters:       clusters,
		})
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, err = w.Write(respb)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func switchCluster() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if len(name) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  clusterCookieName,
			Value: name,
			Path:  "/",
		})
		w.Header().Set("Location", "/")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}
}
