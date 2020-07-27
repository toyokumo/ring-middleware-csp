(ns ring-middleware-csp.core
  (:require
   [clojure.string :as str]))

(defn- value->str [value]
  (->> (if (coll? value) value [value])
       (map #(if (keyword? %)
               (str "'" (name %) "'")
               %))
       (str/join " ")))

(defn compose
  "Make string value for CSP header from policy map"
  [policy]
  (->> policy
       (map (fn [[d v]] (str (name d) " " (value->str v))))
       (str/join ";")))

(defn wrap-csp
  "Middleware that adds Content-Security-Policy header.
  Accepts the following options:
  :policy           - CSP in {directive-name directive-values} format. See README for details.
  :report-only?     - true if Use Content-Security-Policy-Report-Only Header.
  :policy-generator - Function that dynamically generate policy map from request.
  :report-handler   - map including following keys.
    :path           - report uri path.
    :handler        - Function that process request and return response."
  [handler {:keys [policy report-only? policy-generator report-handler]}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        header-value (compose policy)]
    (fn [{:keys [uri] :as req}]
      (if (and (:path report-handler)
               (= uri (:path report-handler)))
        ((:handler report-handler) req)
        (let [res (handler req)
              header-value (or (when policy-generator
                                 (when-let [p (policy-generator req)]
                                   (compose p)))
                               header-value)]
          (assoc-in res [:headers header-name] header-value))))))
