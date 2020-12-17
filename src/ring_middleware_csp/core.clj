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

(def ^:private make-template
  (memoize (fn [policy]
             (let [nonce-placeholder ";%NONCE%;"
                   tmpl (-> (compose policy nonce-placeholder)
                            (str/split (re-pattern nonce-placeholder)))]
               (fn [nonce]
                 (str/join nonce tmpl))))))

(defn- no-nonce-middleware
  [handler {:keys [policy report-only? policy-generator report-handler report-uri]}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        default-policy (compose policy)
        compose* (when policy-generator (memoize compose))]
    (fn [{:keys [uri] :as req}]
      (if (and report-uri (= uri report-uri))
        (report-handler req)
        (let [res (handler req)
              header-value (or (when policy-generator
                                 (some-> (policy-generator req)
                                         (compose*)))
                               default-policy)]
          (assoc-in res [:headers header-name] header-value))))))

(defn- nonce-middleware
  [handler {:keys [policy report-only? policy-generator report-handler
                   report-uri nonce-generator]}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        nonce-generator (or nonce-generator (make-nonce-generator))
        policy-tmpl (make-template policy)]
    (fn [{:keys [uri] :as req}]
      (if (and report-uri (= uri report-uri))
        (report-handler req)
        (let [nonce (nonce-generator)
              res (handler (assoc req :csp-nonce nonce))
              header-value (let [tmpl (or (when policy-generator
                                            (some-> (policy-generator req)
                                                    (make-template)))
                                          policy-tmpl)]
                             (tmpl nonce))]
          (assoc-in res [:headers header-name] header-value))))))

(defn wrap-csp
  "Middleware that adds Content-Security-Policy header.
  Accepts the following options:
  :policy           - CSP in {directive-name directive-values} format. See README for details.
  :report-only?     - true if Use Content-Security-Policy-Report-Only Header.
  :policy-generator - function that dynamically generate policy map from request.
  :report-handler   - function that process request and return response.
  :report-uri       - specify the path to use report-handler.
  :use-nonce?       - boolean. if true, generate nonce and replace policy value :nonce to `nonce-xxxxxxxx`.
                      default: true
  :nonce-generator  - custom function that generate nonce string.
                      default implementation by SecureRandom class."
  [handler {:keys [report-handler report-uri use-nonce?]
            :or {use-nonce? true}
            :as opts}]
  (assert (= (nil? report-uri) (nil? report-handler))
          "if use report-handler or report-uri, must set both report-handler and report-uri")
  (if use-nonce?
    (nonce-middleware handler opts)
    (no-nonce-middleware handler opts)))
