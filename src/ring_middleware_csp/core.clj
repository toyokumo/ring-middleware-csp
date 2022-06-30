(ns ring-middleware-csp.core
  (:require
   [clojure.string :as str])
  (:import
   (java.security
    SecureRandom)
   (java.util
    Base64)))

(defn- make-nonce-generator []
  (let [sr (if (.startsWith (System/getProperty "os.name") "Windows")
             (SecureRandom.)
             (SecureRandom/getInstance "NativePRNGNonBlocking"))
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

(defn- ->directive
  [nonce [d v]]
  (case v
    true (name d)
    (false nil) nil
    (str (name d) " " (value->str v nonce))))

(defn compose
  "Make string value for CSP header from policy map"
  ([policy]
   (compose policy nil))
  ([policy nonce]
   (->> (for [entry policy
              :let [directive-str (->directive nonce entry)]
              :when (seq directive-str)]
          directive-str)
        (str/join ";"))))

(defn parse
  "Make policy map from CSP header string value"
  [policy-str]
  (->> (str/split policy-str #";")
       (map (fn [v]
              (let [[name & values] (str/split (str/trim v) #" +")
                    values (map #(cond
                                   (str/starts-with? % "'nonce-")
                                   :nonce

                                   (str/starts-with? % "'")
                                   (keyword (subs % 1 (dec (count %))))

                                   :else
                                   %)
                                values)]
                [(keyword name) (if (seq values)
                                  values
                                  true)])))
       (into {})))

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
    (fn no-nonce-middleware-handler
      ([{:keys [uri] :as req}]
       (if (and report-uri (= uri report-uri))
         (report-handler req)
         (let [res (handler req)
               header-value (or (when policy-generator
                                  (some-> (policy-generator req)
                                          (compose*)))
                                default-policy)]
           (assoc-in res [:headers header-name] header-value))))
      ([{:keys [uri] :as req} respond raise]
       (if (and report-uri (= uri report-uri))
         (respond (report-handler req))
         (handler req
                  (let [header-value (or (when policy-generator
                                           (some-> (policy-generator req)
                                                   (compose*)))
                                         default-policy)]
                    #(respond (assoc-in % [:headers header-name] header-value)))
                  raise))))))

(defn- nonce-middleware
  [handler {:keys [policy report-only? policy-generator report-handler
                   report-uri nonce-generator]}]
  (let [header-name (if report-only?
                      "Content-Security-Policy-Report-Only"
                      "Content-Security-Policy")
        nonce-generator (or nonce-generator (make-nonce-generator))
        policy-tmpl (make-template policy)]
    (fn nonce-middleware-handler
      ([{:keys [uri] :as req}]
       (if (and report-uri (= uri report-uri))
         (report-handler req)
         (let [nonce (nonce-generator)
               res (handler (assoc req :csp-nonce nonce))
               header-value (let [tmpl (or (when policy-generator
                                             (some-> (policy-generator req)
                                                     (make-template)))
                                           policy-tmpl)]
                              (tmpl nonce))]
           (assoc-in res [:headers header-name] header-value))))
      ([{:keys [uri] :as req} respond raise]
       (if (and report-uri (= uri report-uri))
         (respond (report-handler req))
         (let [nonce (nonce-generator)
               tmpl (or (when policy-generator
                          (some-> (policy-generator req)
                                  (make-template)))
                        policy-tmpl)]
           (handler (assoc req :csp-nonce nonce)
                    (fn [res]
                      (respond (assoc-in res [:headers header-name] (tmpl nonce))))
                    raise)))))))

(defn wrap-csp
  "Middleware that adds Content-Security-Policy header.
  Accepts the following options:
  :policy           - CSP in {directive-name directive-values} format. See README for details.
  :report-only?     - true if Use Content-Security-Policy-Report-Only Header.
  :policy-generator - function that dynamically generate policy map from request.
  :report-handler   - function that process request and return response.
  :report-uri       - specify the path to use report-handler.
  :use-nonce?       - boolean. if true, generate nonce and replace policy value :nonce to `nonce-xxxxxxxx`.
                      default: false
  :nonce-generator  - custom function that generate nonce string.
                      default implementation by SecureRandom class."
  [handler {:keys [report-handler report-uri use-nonce?]
            :as opts}]
  (assert (= (nil? report-uri) (nil? report-handler))
          "if use report-handler or report-uri, must set both report-handler and report-uri")
  (if use-nonce?
    (nonce-middleware handler opts)
    (no-nonce-middleware handler opts)))
