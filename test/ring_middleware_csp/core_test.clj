(ns ring-middleware-csp.core-test
  (:require
   [clojure.test :refer :all]
   [ring-middleware-csp.core :refer :all]))

(deftest compose-test
  (testing "without nonce"
    (is (= "" (compose {})))
    (is (= "default-src 'self'" (compose {:default-src :self})))
    (is (= "default-src 'self'" (compose {:default-src [:self]})))
    (is (= "default-src 'self' https://example.com;connect-src 'none';script-src 'self' https://script.example.com;style-src 'unsafe-inline' https://style.example.com"
           (compose {:default-src [:self "https://example.com"]
                     :connect-src :none
                     :script-src [:self "https://script.example.com"]
                     :style-src [:unsafe-inline "https://style.example.com"]})))
    (is (= "script-src 'self';report-uri /csp-report-path;report-to csp-endpoint"
           (compose {:script-src [:self]
                     :report-uri "/csp-report-path"
                     :report-to "csp-endpoint"})))
    (is (= "default-src 'self';block-all-mixed-content;script-src 'self'"
           (compose {:default-src [:self]
                     :block-all-mixed-content true
                     :script-src [:self]})))
    (is (= "default-src 'self';script-src 'self'"
           (compose {:default-src [:self]
                     :block-all-mixed-content false
                     :script-src [:self]}))))
  (testing "with nonce"
    (is (= "script-src 'self' 'nonce-abcdefg'"
           (compose {:script-src [:self :nonce]} "abcdefg")))
    (is (= "script-src 'self' 'nonce-abcdefg';style-src 'nonce-abcdefg'"
           (compose {:script-src [:self :nonce]
                     :style-src :nonce}
                    "abcdefg")))))

(deftest parse-test
  (testing "without nonce"
    (is (= {:default-src [:self]} (parse "default-src 'self'")))
    (is (= {:default-src [:self]} (parse "default-src 'self'")))
    (is (= {:default-src [:self "https://example.com"]
            :connect-src [:none]
            :script-src [:self "https://script.example.com"]
            :style-src [:unsafe-inline "https://style.example.com"]}
           (parse "default-src 'self' https://example.com;connect-src 'none';script-src 'self' https://script.example.com;style-src 'unsafe-inline' https://style.example.com")))
    (is (= {:script-src [:self]
            :report-uri ["/csp-report-path"]
            :report-to ["csp-endpoint"]}
           (parse "script-src 'self';report-uri /csp-report-path;report-to csp-endpoint")))
    (is (= {:default-src [:self]
            :block-all-mixed-content true
            :script-src [:self]}
           (parse "default-src 'self';block-all-mixed-content;script-src 'self'"))))
  (testing "with nonce"
    (is (= {:script-src [:self :nonce]}
           (parse "script-src 'self' 'nonce-abcdefg'")))
    (is (= {:script-src [:self :nonce]
            :style-src [:nonce]}
           (parse "script-src 'self' 'nonce-abcdefg';style-src 'nonce-abcdefg'")))))

(deftest wrap-csp-test
  (let [handler (constantly {:status 200 :headers {} :body ""})]
    (is (= "default-src 'self'"
           (get-in ((wrap-csp handler {:policy {:default-src :self}}) {})
                   [:headers "Content-Security-Policy"])))
    (is (= "default-src 'self'"
           (get-in ((wrap-csp handler {:policy {:default-src :self}
                                       :report-only? true}) {})
                   [:headers "Content-Security-Policy-Report-Only"])))))

(deftest policy-generator-test
  (let [handler (constantly {:status 200 :headers {} :body ""})
        generator #(case (:uri %)
                     "/simple-page" {:default-src :none}
                     "/style-page" {:default-src :none
                                    :style-src :self}
                     nil)
        opts {:policy {:default-src :self}
              :policy-generator generator}]
    (is (= "default-src 'none'"
           (get-in ((wrap-csp handler opts) {:uri "/simple-page"})
                   [:headers "Content-Security-Policy"])))
    (is (= "default-src 'none';style-src 'self'"
           (get-in ((wrap-csp handler opts) {:uri "/style-page"})
                   [:headers "Content-Security-Policy"])))
    (is (= "default-src 'self'"
           (get-in ((wrap-csp handler opts) {:uri "/other-page"})
                   [:headers "Content-Security-Policy"])))))

(deftest report-handler-test
  (testing "use report-handler and report-uri"
    (let [handler (constantly {:status 200 :headers {} :body "OK"})
          opts {:policy {:default-src :self}
                :report-handler (fn [req] {:status 204 :headers {} :body ""})
                :report-uri "/csp-report"}]
      (is (= {:status 204 :headers {} :body ""}
             ((wrap-csp handler opts) {:uri "/csp-report"})))
      (is (= {:status 200 :body "OK" :headers {"Content-Security-Policy" "default-src 'self'"}}
             ((wrap-csp handler opts) {:uri "/a/csp-report"})))
      (is (= {:status 200 :body "OK" :headers {"Content-Security-Policy" "default-src 'self'"}}
             ((wrap-csp handler opts) {:uri "/csp-report/1"})))
      (is (= {:status 200 :body "OK" :headers {"Content-Security-Policy" "default-src 'self'"}}
             ((wrap-csp handler opts) {:uri "/"})))))
  (testing "invalid option"
    (let [handler (constantly {:status 200 :headers {} :body "OK"})]
      (is (thrown? AssertionError
            (wrap-csp handler {:policy {:default-src :self}
                               :report-handler (fn [req] {:status 204 :headers {} :body ""})})))
      (is (thrown? AssertionError
            (wrap-csp handler {:policy {:default-src :self}
                               :report-uri "/csp-report"}))))))

(deftest nonce-test
  (testing "enabled"
    (let [nonce-generator (constantly "tHYj7bf2EsYW4J0Fbtp76IWPyw8Hh7B1VYVlx5PQytw=")
          handler (fn [{:keys [csp-nonce] :as req}]
                    {:status 200
                     :headers {}
                     :body (str "<script nonce=\"" csp-nonce "\"></script>")})
          opts {:policy {:default-src :self
                         :script-src :nonce
                         :style-src [:self :nonce]}
                :use-nonce? true
                :nonce-generator nonce-generator}
          expected "default-src 'self';script-src 'nonce-tHYj7bf2EsYW4J0Fbtp76IWPyw8Hh7B1VYVlx5PQytw=';style-src 'self' 'nonce-tHYj7bf2EsYW4J0Fbtp76IWPyw8Hh7B1VYVlx5PQytw='"]
      (is (= {:status 200
              :headers {"Content-Security-Policy" expected}
              :body "<script nonce=\"tHYj7bf2EsYW4J0Fbtp76IWPyw8Hh7B1VYVlx5PQytw=\"></script>"}
             ((wrap-csp handler opts) {})))))
  (testing "disabled"
    (let [nonce-generator #(throw (ex-info "dont use" {}))
          handler (constantly {:status 200 :headers {} :body ""})
          opts {:policy {:default-src :self
                         :script-src :nonce
                         :style-src [:self :nonce]}
                :use-nonce? false
                :nonce-generator nonce-generator}]
      (is (= {:status 200
              :headers {"Content-Security-Policy"
                        "default-src 'self';script-src 'nonce';style-src 'self' 'nonce'"}
              :body ""}
             ((wrap-csp handler opts) {}))))))
