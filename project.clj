(defproject toyokumo/ring-middleware-csp "0.1.1"
  :description "Ring middleware for Content Security Policy"
  :url "https://github.com/toyokumo/ring-middleware-csp"
  :license {:name "Apache, Version 2.0"
            :url "http://www.apache.org/licenses/LICENSE-2.0"}
  :deploy-repositories [["releases" {:url "https://repo.clojars.org" :creds :gpg}]
                        ["snapshots" :clojars]]
  :dependencies [[org.clojure/clojure "1.10.1"]]
  :repl-options {:init-ns ring-middleware-csp.core})
