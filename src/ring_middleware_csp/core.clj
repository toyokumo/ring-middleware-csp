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
  :policy-generator - Functions that dynamically generate policy map from request."
  [handler {:keys [policy report-only? policy-generator]}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        header-value (compose policy)]
    (fn [req]
      (let [res (handler req)
            header-value (or (when policy-generator
                               (when-let [p (policy-generator req)]
                                 (compose p)))
                             header-value)]
        (assoc-in res [:headers header-name] header-value)))))
