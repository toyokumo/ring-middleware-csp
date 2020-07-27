(ns ring-middleware-csp.core
  (:require
   [clojure.string :as str])
  (:import
   (java.security
    SecureRandom)
   (java.util
    Base64)))

(defn- make-nonce-generator []
  (let [sr (SecureRandom/getInstance "NativePRNGNonBlocking")
        be (Base64/getEncoder)]
    (fn []
      (let [ba (byte-array 32)]
        (.nextBytes sr ba)
        (.encodeToString be ba)))))

(defn- value->str [value nonce]
  (->> (if (coll? value) value [value])
       (map #(cond
               (and nonce (= :nonce %)) (str "'nonce-" nonce "'")
               (keyword? %) (str "'" (name %) "'")
               :else %))
       (str/join " ")))

(defn compose
  "Make string value for CSP header from policy map"
  ([policy]
   (compose policy nil))
  ([policy nonce]
   (->> policy
        (map (fn [[d v]] (str (name d) " " (value->str v nonce))))
        (str/join ";"))))

(defn wrap-csp
  "Middleware that adds Content-Security-Policy header.
  Accepts the following options:
  :policy           - CSP in {directive-name directive-values} format. See README for details.
  :report-only?     - true if Use Content-Security-Policy-Report-Only Header.
  :policy-generator - Function that dynamically generate policy map from request.
  :report-handler   - map including following keys.
    :path           - report uri path.
    :handler        - Function that process request and return response.
  :use-nonce?       - boolean. if true, generate nonce and replace policy value :nonce to `nonce-xxxxxxxx`.
                      default: true
  :nonce-generator  - custom function that generate nonce string.
                      default implementation by SecureRandom class."
  [handler {:keys [policy report-only? policy-generator report-handler use-nonce? nonce-generator]
            :or {use-nonce? true}}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        nonce-generator (when use-nonce?
                          (or nonce-generator
                              (make-nonce-generator)))]
    (fn [{:keys [uri] :as req}]
      (if (and (:path report-handler)
               (= uri (:path report-handler)))
        ((:handler report-handler) req)
        (let [nonce (when use-nonce? (nonce-generator))
              res (handler (if use-nonce?
                             (assoc req :csp-nonce nonce)
                             req))
              header-value (compose (or (when policy-generator
                                          (policy-generator req))
                                        policy)
                                    nonce)]
          (assoc-in res [:headers header-name] header-value))))))
